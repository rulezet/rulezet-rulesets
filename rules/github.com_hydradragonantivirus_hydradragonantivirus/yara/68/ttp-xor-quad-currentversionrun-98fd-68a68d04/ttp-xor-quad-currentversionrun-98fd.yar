rule TTP_XOR_QUAD_CurrentVersionRun_98fd {
  strings:
    $key_98fd = { cb 92 [2] ef 9c [2] c4 b0 [2] ea 92 [2] fe 89 [2] f1 93 [2] ef 8e [2] ed 8f [2] f6 89 [2] ea 8e [2] f6 a1 }

  condition:
    any of them
}