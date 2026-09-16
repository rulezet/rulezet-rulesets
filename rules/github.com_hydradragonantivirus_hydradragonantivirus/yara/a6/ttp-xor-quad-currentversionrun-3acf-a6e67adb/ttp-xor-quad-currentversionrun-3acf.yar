rule TTP_XOR_QUAD_CurrentVersionRun_3acf {
  strings:
    $key_3acf = { 69 a0 [2] 4d ae [2] 66 82 [2] 48 a0 [2] 5c bb [2] 53 a1 [2] 4d bc [2] 4f bd [2] 54 bb [2] 48 bc [2] 54 93 }

  condition:
    any of them
}