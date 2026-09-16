rule TTP_XOR_QUAD_CurrentVersionRun_b9da {
  strings:
    $key_b9da = { ea b5 [2] ce bb [2] e5 97 [2] cb b5 [2] df ae [2] d0 b4 [2] ce a9 [2] cc a8 [2] d7 ae [2] cb a9 [2] d7 86 }

  condition:
    any of them
}