rule TTP_XOR_QUAD_CurrentVersionRun_985e {
  strings:
    $key_985e = { cb 31 [2] ef 3f [2] c4 13 [2] ea 31 [2] fe 2a [2] f1 30 [2] ef 2d [2] ed 2c [2] f6 2a [2] ea 2d [2] f6 02 }

  condition:
    any of them
}