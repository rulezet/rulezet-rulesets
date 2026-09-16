rule TTP_XOR_QUAD_CurrentVersionRun_9869 {
  strings:
    $key_9869 = { cb 06 [2] ef 08 [2] c4 24 [2] ea 06 [2] fe 1d [2] f1 07 [2] ef 1a [2] ed 1b [2] f6 1d [2] ea 1a [2] f6 35 }

  condition:
    any of them
}