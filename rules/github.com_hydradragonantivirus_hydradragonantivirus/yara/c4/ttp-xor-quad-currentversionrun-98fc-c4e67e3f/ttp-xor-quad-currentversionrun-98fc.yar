rule TTP_XOR_QUAD_CurrentVersionRun_98fc {
  strings:
    $key_98fc = { cb 93 [2] ef 9d [2] c4 b1 [2] ea 93 [2] fe 88 [2] f1 92 [2] ef 8f [2] ed 8e [2] f6 88 [2] ea 8f [2] f6 a0 }

  condition:
    any of them
}