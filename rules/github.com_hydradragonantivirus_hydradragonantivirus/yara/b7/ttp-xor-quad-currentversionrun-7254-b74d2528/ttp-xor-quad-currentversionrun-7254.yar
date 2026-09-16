rule TTP_XOR_QUAD_CurrentVersionRun_7254 {
  strings:
    $key_7254 = { 21 3b [2] 05 35 [2] 2e 19 [2] 00 3b [2] 14 20 [2] 1b 3a [2] 05 27 [2] 07 26 [2] 1c 20 [2] 00 27 [2] 1c 08 }

  condition:
    any of them
}