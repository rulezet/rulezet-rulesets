rule TTP_XOR_QUAD_CurrentVersionRun_98f7 {
  strings:
    $key_98f7 = { cb 98 [2] ef 96 [2] c4 ba [2] ea 98 [2] fe 83 [2] f1 99 [2] ef 84 [2] ed 85 [2] f6 83 [2] ea 84 [2] f6 ab }

  condition:
    any of them
}