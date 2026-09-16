rule TTP_XOR_QUAD_CurrentVersionRun_398d {
  strings:
    $key_398d = { 6a e2 [2] 4e ec [2] 65 c0 [2] 4b e2 [2] 5f f9 [2] 50 e3 [2] 4e fe [2] 4c ff [2] 57 f9 [2] 4b fe [2] 57 d1 }

  condition:
    any of them
}