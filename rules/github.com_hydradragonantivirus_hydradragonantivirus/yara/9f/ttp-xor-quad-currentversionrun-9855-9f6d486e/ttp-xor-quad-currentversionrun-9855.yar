rule TTP_XOR_QUAD_CurrentVersionRun_9855 {
  strings:
    $key_9855 = { cb 3a [2] ef 34 [2] c4 18 [2] ea 3a [2] fe 21 [2] f1 3b [2] ef 26 [2] ed 27 [2] f6 21 [2] ea 26 [2] f6 09 }

  condition:
    any of them
}