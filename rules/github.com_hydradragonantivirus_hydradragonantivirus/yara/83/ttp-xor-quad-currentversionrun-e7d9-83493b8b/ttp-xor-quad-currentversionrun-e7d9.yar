rule TTP_XOR_QUAD_CurrentVersionRun_e7d9 {
  strings:
    $key_e7d9 = { b4 b6 [2] 90 b8 [2] bb 94 [2] 95 b6 [2] 81 ad [2] 8e b7 [2] 90 aa [2] 92 ab [2] 89 ad [2] 95 aa [2] 89 85 }

  condition:
    any of them
}