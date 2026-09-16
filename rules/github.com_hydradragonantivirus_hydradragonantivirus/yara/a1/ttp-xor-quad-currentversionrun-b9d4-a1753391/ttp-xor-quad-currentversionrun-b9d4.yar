rule TTP_XOR_QUAD_CurrentVersionRun_b9d4 {
  strings:
    $key_b9d4 = { ea bb [2] ce b5 [2] e5 99 [2] cb bb [2] df a0 [2] d0 ba [2] ce a7 [2] cc a6 [2] d7 a0 [2] cb a7 [2] d7 88 }

  condition:
    any of them
}