rule TTP_XOR_QUAD_CurrentVersionRun_72d9 {
  strings:
    $key_72d9 = { 21 b6 [2] 05 b8 [2] 2e 94 [2] 00 b6 [2] 14 ad [2] 1b b7 [2] 05 aa [2] 07 ab [2] 1c ad [2] 00 aa [2] 1c 85 }

  condition:
    any of them
}