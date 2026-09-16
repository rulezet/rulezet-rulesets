rule TTP_XOR_QUAD_CurrentVersionRun_4fca {
  strings:
    $key_4fca = { 1c a5 [2] 38 ab [2] 13 87 [2] 3d a5 [2] 29 be [2] 26 a4 [2] 38 b9 [2] 3a b8 [2] 21 be [2] 3d b9 [2] 21 96 }

  condition:
    any of them
}