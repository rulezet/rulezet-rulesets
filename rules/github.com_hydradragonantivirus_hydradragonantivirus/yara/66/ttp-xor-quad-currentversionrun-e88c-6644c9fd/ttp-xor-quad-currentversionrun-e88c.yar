rule TTP_XOR_QUAD_CurrentVersionRun_e88c {
  strings:
    $key_e88c = { bb e3 [2] 9f ed [2] b4 c1 [2] 9a e3 [2] 8e f8 [2] 81 e2 [2] 9f ff [2] 9d fe [2] 86 f8 [2] 9a ff [2] 86 d0 }

  condition:
    any of them
}