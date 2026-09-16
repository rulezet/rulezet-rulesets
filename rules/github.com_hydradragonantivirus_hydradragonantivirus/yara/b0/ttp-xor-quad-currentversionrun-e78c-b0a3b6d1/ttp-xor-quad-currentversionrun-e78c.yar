rule TTP_XOR_QUAD_CurrentVersionRun_e78c {
  strings:
    $key_e78c = { b4 e3 [2] 90 ed [2] bb c1 [2] 95 e3 [2] 81 f8 [2] 8e e2 [2] 90 ff [2] 92 fe [2] 89 f8 [2] 95 ff [2] 89 d0 }

  condition:
    any of them
}