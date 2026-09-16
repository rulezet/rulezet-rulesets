rule TTP_XOR_QUAD_CurrentVersionRun_752b {
  strings:
    $key_752b = { 26 44 [2] 02 4a [2] 29 66 [2] 07 44 [2] 13 5f [2] 1c 45 [2] 02 58 [2] 00 59 [2] 1b 5f [2] 07 58 [2] 1b 77 }

  condition:
    any of them
}