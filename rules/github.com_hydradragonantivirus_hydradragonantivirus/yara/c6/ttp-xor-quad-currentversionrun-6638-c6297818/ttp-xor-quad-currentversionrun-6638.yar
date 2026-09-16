rule TTP_XOR_QUAD_CurrentVersionRun_6638 {
  strings:
    $key_6638 = { 35 57 [2] 11 59 [2] 3a 75 [2] 14 57 [2] 00 4c [2] 0f 56 [2] 11 4b [2] 13 4a [2] 08 4c [2] 14 4b [2] 08 64 }

  condition:
    any of them
}