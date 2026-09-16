rule TTP_XOR_QUAD_CurrentVersionRun_2fd9 {
  strings:
    $key_2fd9 = { 7c b6 [2] 58 b8 [2] 73 94 [2] 5d b6 [2] 49 ad [2] 46 b7 [2] 58 aa [2] 5a ab [2] 41 ad [2] 5d aa [2] 41 85 }

  condition:
    any of them
}