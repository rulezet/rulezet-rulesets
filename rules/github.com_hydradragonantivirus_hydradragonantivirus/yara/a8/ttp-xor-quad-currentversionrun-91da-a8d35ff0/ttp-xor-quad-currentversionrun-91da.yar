rule TTP_XOR_QUAD_CurrentVersionRun_91da {
  strings:
    $key_91da = { c2 b5 [2] e6 bb [2] cd 97 [2] e3 b5 [2] f7 ae [2] f8 b4 [2] e6 a9 [2] e4 a8 [2] ff ae [2] e3 a9 [2] ff 86 }

  condition:
    any of them
}