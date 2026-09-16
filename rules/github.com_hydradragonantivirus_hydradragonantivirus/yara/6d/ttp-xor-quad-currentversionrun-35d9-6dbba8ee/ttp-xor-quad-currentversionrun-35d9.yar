rule TTP_XOR_QUAD_CurrentVersionRun_35d9 {
  strings:
    $key_35d9 = { 66 b6 [2] 42 b8 [2] 69 94 [2] 47 b6 [2] 53 ad [2] 5c b7 [2] 42 aa [2] 40 ab [2] 5b ad [2] 47 aa [2] 5b 85 }

  condition:
    any of them
}