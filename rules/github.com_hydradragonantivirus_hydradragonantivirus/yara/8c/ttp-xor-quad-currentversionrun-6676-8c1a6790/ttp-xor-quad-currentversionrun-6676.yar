rule TTP_XOR_QUAD_CurrentVersionRun_6676 {
  strings:
    $key_6676 = { 35 19 [2] 11 17 [2] 3a 3b [2] 14 19 [2] 00 02 [2] 0f 18 [2] 11 05 [2] 13 04 [2] 08 02 [2] 14 05 [2] 08 2a }

  condition:
    any of them
}