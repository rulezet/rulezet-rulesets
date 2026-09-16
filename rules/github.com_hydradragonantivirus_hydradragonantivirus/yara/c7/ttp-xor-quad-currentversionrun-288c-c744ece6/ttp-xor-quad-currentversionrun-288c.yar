rule TTP_XOR_QUAD_CurrentVersionRun_288c {
  strings:
    $key_288c = { 7b e3 [2] 5f ed [2] 74 c1 [2] 5a e3 [2] 4e f8 [2] 41 e2 [2] 5f ff [2] 5d fe [2] 46 f8 [2] 5a ff [2] 46 d0 }

  condition:
    any of them
}