rule TTP_XOR_QUAD_CurrentVersionRun_75d6 {
  strings:
    $key_75d6 = { 26 b9 [2] 02 b7 [2] 29 9b [2] 07 b9 [2] 13 a2 [2] 1c b8 [2] 02 a5 [2] 00 a4 [2] 1b a2 [2] 07 a5 [2] 1b 8a }

  condition:
    any of them
}