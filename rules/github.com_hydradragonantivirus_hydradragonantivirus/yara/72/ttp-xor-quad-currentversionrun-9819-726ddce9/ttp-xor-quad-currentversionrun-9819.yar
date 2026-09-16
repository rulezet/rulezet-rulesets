rule TTP_XOR_QUAD_CurrentVersionRun_9819 {
  strings:
    $key_9819 = { cb 76 [2] ef 78 [2] c4 54 [2] ea 76 [2] fe 6d [2] f1 77 [2] ef 6a [2] ed 6b [2] f6 6d [2] ea 6a [2] f6 45 }

  condition:
    any of them
}