rule TTP_XOR_QUAD_CurrentVersionRun_e2d9 {
  strings:
    $key_e2d9 = { b1 b6 [2] 95 b8 [2] be 94 [2] 90 b6 [2] 84 ad [2] 8b b7 [2] 95 aa [2] 97 ab [2] 8c ad [2] 90 aa [2] 8c 85 }

  condition:
    any of them
}