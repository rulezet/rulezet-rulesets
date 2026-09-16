rule TTP_XOR_QUAD_CurrentVersionRun_0748 {
  strings:
    $key_0748 = { 54 27 [2] 70 29 [2] 5b 05 [2] 75 27 [2] 61 3c [2] 6e 26 [2] 70 3b [2] 72 3a [2] 69 3c [2] 75 3b [2] 69 14 }

  condition:
    any of them
}