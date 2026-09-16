rule TTP_XOR_QUAD_CurrentVersionRun_98ea {
  strings:
    $key_98ea = { cb 85 [2] ef 8b [2] c4 a7 [2] ea 85 [2] fe 9e [2] f1 84 [2] ef 99 [2] ed 98 [2] f6 9e [2] ea 99 [2] f6 b6 }

  condition:
    any of them
}