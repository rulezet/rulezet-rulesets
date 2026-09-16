rule TTP_XOR_QUAD_CurrentVersionRun_98b3 {
  strings:
    $key_98b3 = { cb dc [2] ef d2 [2] c4 fe [2] ea dc [2] fe c7 [2] f1 dd [2] ef c0 [2] ed c1 [2] f6 c7 [2] ea c0 [2] f6 ef }

  condition:
    any of them
}