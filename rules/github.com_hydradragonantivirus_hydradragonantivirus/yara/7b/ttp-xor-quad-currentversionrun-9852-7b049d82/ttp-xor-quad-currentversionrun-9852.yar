rule TTP_XOR_QUAD_CurrentVersionRun_9852 {
  strings:
    $key_9852 = { cb 3d [2] ef 33 [2] c4 1f [2] ea 3d [2] fe 26 [2] f1 3c [2] ef 21 [2] ed 20 [2] f6 26 [2] ea 21 [2] f6 0e }

  condition:
    any of them
}