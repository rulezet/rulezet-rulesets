rule TTP_XOR_QUAD_CurrentVersionRun_6fd9 {
  strings:
    $key_6fd9 = { 3c b6 [2] 18 b8 [2] 33 94 [2] 1d b6 [2] 09 ad [2] 06 b7 [2] 18 aa [2] 1a ab [2] 01 ad [2] 1d aa [2] 01 85 }

  condition:
    any of them
}