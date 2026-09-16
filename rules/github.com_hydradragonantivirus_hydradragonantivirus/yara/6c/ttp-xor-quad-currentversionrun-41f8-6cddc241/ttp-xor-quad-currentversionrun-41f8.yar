rule TTP_XOR_QUAD_CurrentVersionRun_41f8 {
  strings:
    $key_41f8 = { 12 97 [2] 36 99 [2] 1d b5 [2] 33 97 [2] 27 8c [2] 28 96 [2] 36 8b [2] 34 8a [2] 2f 8c [2] 33 8b [2] 2f a4 }

  condition:
    any of them
}