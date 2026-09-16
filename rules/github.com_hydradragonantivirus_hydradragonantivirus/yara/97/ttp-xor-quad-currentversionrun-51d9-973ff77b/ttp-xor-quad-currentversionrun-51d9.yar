rule TTP_XOR_QUAD_CurrentVersionRun_51d9 {
  strings:
    $key_51d9 = { 02 b6 [2] 26 b8 [2] 0d 94 [2] 23 b6 [2] 37 ad [2] 38 b7 [2] 26 aa [2] 24 ab [2] 3f ad [2] 23 aa [2] 3f 85 }

  condition:
    any of them
}