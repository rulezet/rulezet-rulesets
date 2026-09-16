rule TTP_XOR_QUAD_CurrentVersionRun_b590 {
  strings:
    $key_b590 = { e6 ff [2] c2 f1 [2] e9 dd [2] c7 ff [2] d3 e4 [2] dc fe [2] c2 e3 [2] c0 e2 [2] db e4 [2] c7 e3 [2] db cc }

  condition:
    any of them
}