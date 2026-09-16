rule TTP_XOR_QUAD_CurrentVersionRun_e98d {
  strings:
    $key_e98d = { ba e2 [2] 9e ec [2] b5 c0 [2] 9b e2 [2] 8f f9 [2] 80 e3 [2] 9e fe [2] 9c ff [2] 87 f9 [2] 9b fe [2] 87 d1 }

  condition:
    any of them
}