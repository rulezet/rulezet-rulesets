rule TTP_XOR_QUAD_CurrentVersionRun_984c {
  strings:
    $key_984c = { cb 23 [2] ef 2d [2] c4 01 [2] ea 23 [2] fe 38 [2] f1 22 [2] ef 3f [2] ed 3e [2] f6 38 [2] ea 3f [2] f6 10 }

  condition:
    any of them
}