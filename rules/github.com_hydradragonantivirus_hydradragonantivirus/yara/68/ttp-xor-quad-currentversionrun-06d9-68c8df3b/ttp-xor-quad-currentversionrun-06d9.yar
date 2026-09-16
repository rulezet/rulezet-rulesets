rule TTP_XOR_QUAD_CurrentVersionRun_06d9 {
  strings:
    $key_06d9 = { 55 b6 [2] 71 b8 [2] 5a 94 [2] 74 b6 [2] 60 ad [2] 6f b7 [2] 71 aa [2] 73 ab [2] 68 ad [2] 74 aa [2] 68 85 }

  condition:
    any of them
}