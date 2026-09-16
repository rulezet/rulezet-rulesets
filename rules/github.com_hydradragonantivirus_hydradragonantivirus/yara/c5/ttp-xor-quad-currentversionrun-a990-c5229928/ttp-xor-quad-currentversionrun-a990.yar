rule TTP_XOR_QUAD_CurrentVersionRun_a990 {
  strings:
    $key_a990 = { fa ff [2] de f1 [2] f5 dd [2] db ff [2] cf e4 [2] c0 fe [2] de e3 [2] dc e2 [2] c7 e4 [2] db e3 [2] c7 cc }

  condition:
    any of them
}