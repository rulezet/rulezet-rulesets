rule TTP_XOR_QUAD_CurrentVersionRun_24d9 {
  strings:
    $key_24d9 = { 77 b6 [2] 53 b8 [2] 78 94 [2] 56 b6 [2] 42 ad [2] 4d b7 [2] 53 aa [2] 51 ab [2] 4a ad [2] 56 aa [2] 4a 85 }

  condition:
    any of them
}