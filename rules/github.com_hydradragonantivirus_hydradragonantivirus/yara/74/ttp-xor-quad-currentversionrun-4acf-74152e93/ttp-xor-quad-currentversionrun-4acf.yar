rule TTP_XOR_QUAD_CurrentVersionRun_4acf {
  strings:
    $key_4acf = { 19 a0 [2] 3d ae [2] 16 82 [2] 38 a0 [2] 2c bb [2] 23 a1 [2] 3d bc [2] 3f bd [2] 24 bb [2] 38 bc [2] 24 93 }

  condition:
    any of them
}