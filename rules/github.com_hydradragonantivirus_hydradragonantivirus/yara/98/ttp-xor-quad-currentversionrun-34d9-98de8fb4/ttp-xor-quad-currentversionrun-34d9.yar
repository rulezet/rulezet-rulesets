rule TTP_XOR_QUAD_CurrentVersionRun_34d9 {
  strings:
    $key_34d9 = { 67 b6 [2] 43 b8 [2] 68 94 [2] 46 b6 [2] 52 ad [2] 5d b7 [2] 43 aa [2] 41 ab [2] 5a ad [2] 46 aa [2] 5a 85 }

  condition:
    any of them
}