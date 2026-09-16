rule TTP_XOR_QUAD_CurrentVersionRun_6614 {
  strings:
    $key_6614 = { 35 7b [2] 11 75 [2] 3a 59 [2] 14 7b [2] 00 60 [2] 0f 7a [2] 11 67 [2] 13 66 [2] 08 60 [2] 14 67 [2] 08 48 }

  condition:
    any of them
}