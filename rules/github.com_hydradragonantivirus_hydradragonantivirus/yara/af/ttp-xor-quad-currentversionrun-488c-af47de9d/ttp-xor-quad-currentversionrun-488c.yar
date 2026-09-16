rule TTP_XOR_QUAD_CurrentVersionRun_488c {
  strings:
    $key_488c = { 1b e3 [2] 3f ed [2] 14 c1 [2] 3a e3 [2] 2e f8 [2] 21 e2 [2] 3f ff [2] 3d fe [2] 26 f8 [2] 3a ff [2] 26 d0 }

  condition:
    any of them
}