rule TTP_XOR_QUAD_CurrentVersionRun_7219 {
  strings:
    $key_7219 = { 21 76 [2] 05 78 [2] 2e 54 [2] 00 76 [2] 14 6d [2] 1b 77 [2] 05 6a [2] 07 6b [2] 1c 6d [2] 00 6a [2] 1c 45 }

  condition:
    any of them
}