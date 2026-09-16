rule TTP_XOR_QUAD_CurrentVersionRun_4655 {
  strings:
    $key_4655 = { 15 3a [2] 31 34 [2] 1a 18 [2] 34 3a [2] 20 21 [2] 2f 3b [2] 31 26 [2] 33 27 [2] 28 21 [2] 34 26 [2] 28 09 }

  condition:
    any of them
}