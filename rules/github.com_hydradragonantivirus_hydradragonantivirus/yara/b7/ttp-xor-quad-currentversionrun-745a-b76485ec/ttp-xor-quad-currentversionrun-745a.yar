rule TTP_XOR_QUAD_CurrentVersionRun_745a {
  strings:
    $key_745a = { 27 35 [2] 03 3b [2] 28 17 [2] 06 35 [2] 12 2e [2] 1d 34 [2] 03 29 [2] 01 28 [2] 1a 2e [2] 06 29 [2] 1a 06 }

  condition:
    any of them
}