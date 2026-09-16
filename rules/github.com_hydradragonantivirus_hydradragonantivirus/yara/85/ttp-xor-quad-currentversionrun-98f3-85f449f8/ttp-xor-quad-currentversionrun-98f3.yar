rule TTP_XOR_QUAD_CurrentVersionRun_98f3 {
  strings:
    $key_98f3 = { cb 9c [2] ef 92 [2] c4 be [2] ea 9c [2] fe 87 [2] f1 9d [2] ef 80 [2] ed 81 [2] f6 87 [2] ea 80 [2] f6 af }

  condition:
    any of them
}