rule TTP_XOR_QUAD_CurrentVersionRun_53c2 {
  strings:
    $key_53c2 = { 00 ad [2] 24 a3 [2] 0f 8f [2] 21 ad [2] 35 b6 [2] 3a ac [2] 24 b1 [2] 26 b0 [2] 3d b6 [2] 21 b1 [2] 3d 9e }

  condition:
    any of them
}