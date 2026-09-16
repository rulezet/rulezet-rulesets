rule TTP_XOR_QUAD_CurrentVersionRun_03d9 {
  strings:
    $key_03d9 = { 50 b6 [2] 74 b8 [2] 5f 94 [2] 71 b6 [2] 65 ad [2] 6a b7 [2] 74 aa [2] 76 ab [2] 6d ad [2] 71 aa [2] 6d 85 }

  condition:
    any of them
}