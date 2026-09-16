rule TTP_XOR_QUAD_CurrentVersionRun_51c8 {
  strings:
    $key_51c8 = { 02 a7 [2] 26 a9 [2] 0d 85 [2] 23 a7 [2] 37 bc [2] 38 a6 [2] 26 bb [2] 24 ba [2] 3f bc [2] 23 bb [2] 3f 94 }

  condition:
    any of them
}