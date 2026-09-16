rule TTP_XOR_QUAD_CurrentVersionRun_13d9 {
  strings:
    $key_13d9 = { 40 b6 [2] 64 b8 [2] 4f 94 [2] 61 b6 [2] 75 ad [2] 7a b7 [2] 64 aa [2] 66 ab [2] 7d ad [2] 61 aa [2] 7d 85 }

  condition:
    any of them
}