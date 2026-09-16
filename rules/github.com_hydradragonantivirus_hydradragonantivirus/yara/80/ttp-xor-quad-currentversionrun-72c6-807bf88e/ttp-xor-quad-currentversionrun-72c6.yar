rule TTP_XOR_QUAD_CurrentVersionRun_72c6 {
  strings:
    $key_72c6 = { 21 a9 [2] 05 a7 [2] 2e 8b [2] 00 a9 [2] 14 b2 [2] 1b a8 [2] 05 b5 [2] 07 b4 [2] 1c b2 [2] 00 b5 [2] 1c 9a }

  condition:
    any of them
}