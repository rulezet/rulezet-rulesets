rule TTP_XOR_QUAD_CurrentVersionRun_7504 {
  strings:
    $key_7504 = { 26 6b [2] 02 65 [2] 29 49 [2] 07 6b [2] 13 70 [2] 1c 6a [2] 02 77 [2] 00 76 [2] 1b 70 [2] 07 77 [2] 1b 58 }

  condition:
    any of them
}