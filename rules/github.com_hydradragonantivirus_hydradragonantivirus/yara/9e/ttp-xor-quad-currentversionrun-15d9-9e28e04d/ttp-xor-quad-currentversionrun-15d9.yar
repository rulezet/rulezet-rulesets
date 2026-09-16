rule TTP_XOR_QUAD_CurrentVersionRun_15d9 {
  strings:
    $key_15d9 = { 46 b6 [2] 62 b8 [2] 49 94 [2] 67 b6 [2] 73 ad [2] 7c b7 [2] 62 aa [2] 60 ab [2] 7b ad [2] 67 aa [2] 7b 85 }

  condition:
    any of them
}