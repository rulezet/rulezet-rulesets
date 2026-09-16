rule TTP_XOR_QUAD_CurrentVersionRun_8490 {
  strings:
    $key_8490 = { d7 ff [2] f3 f1 [2] d8 dd [2] f6 ff [2] e2 e4 [2] ed fe [2] f3 e3 [2] f1 e2 [2] ea e4 [2] f6 e3 [2] ea cc }

  condition:
    any of them
}