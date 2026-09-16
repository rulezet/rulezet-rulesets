rule TTP_XOR_QUAD_CurrentVersionRun_72c5 {
  strings:
    $key_72c5 = { 21 aa [2] 05 a4 [2] 2e 88 [2] 00 aa [2] 14 b1 [2] 1b ab [2] 05 b6 [2] 07 b7 [2] 1c b1 [2] 00 b6 [2] 1c 99 }

  condition:
    any of them
}