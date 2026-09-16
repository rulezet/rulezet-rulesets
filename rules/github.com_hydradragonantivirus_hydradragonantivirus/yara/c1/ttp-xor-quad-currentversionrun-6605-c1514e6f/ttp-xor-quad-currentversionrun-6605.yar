rule TTP_XOR_QUAD_CurrentVersionRun_6605 {
  strings:
    $key_6605 = { 35 6a [2] 11 64 [2] 3a 48 [2] 14 6a [2] 00 71 [2] 0f 6b [2] 11 76 [2] 13 77 [2] 08 71 [2] 14 76 [2] 08 59 }

  condition:
    any of them
}