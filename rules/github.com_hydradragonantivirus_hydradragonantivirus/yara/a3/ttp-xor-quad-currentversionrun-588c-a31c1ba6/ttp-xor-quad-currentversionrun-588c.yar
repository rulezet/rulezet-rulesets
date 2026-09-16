rule TTP_XOR_QUAD_CurrentVersionRun_588c {
  strings:
    $key_588c = { 0b e3 [2] 2f ed [2] 04 c1 [2] 2a e3 [2] 3e f8 [2] 31 e2 [2] 2f ff [2] 2d fe [2] 36 f8 [2] 2a ff [2] 36 d0 }

  condition:
    any of them
}