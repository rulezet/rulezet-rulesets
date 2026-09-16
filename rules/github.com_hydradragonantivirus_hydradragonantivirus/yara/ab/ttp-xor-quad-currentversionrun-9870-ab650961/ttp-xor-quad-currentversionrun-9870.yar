rule TTP_XOR_QUAD_CurrentVersionRun_9870 {
  strings:
    $key_9870 = { cb 1f [2] ef 11 [2] c4 3d [2] ea 1f [2] fe 04 [2] f1 1e [2] ef 03 [2] ed 02 [2] f6 04 [2] ea 03 [2] f6 2c }

  condition:
    any of them
}