rule TTP_XOR_QUAD_CurrentVersionRun_4648 {
  strings:
    $key_4648 = { 15 27 [2] 31 29 [2] 1a 05 [2] 34 27 [2] 20 3c [2] 2f 26 [2] 31 3b [2] 33 3a [2] 28 3c [2] 34 3b [2] 28 14 }

  condition:
    any of them
}