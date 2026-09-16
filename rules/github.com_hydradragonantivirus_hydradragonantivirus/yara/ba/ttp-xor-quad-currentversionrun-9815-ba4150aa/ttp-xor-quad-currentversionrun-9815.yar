rule TTP_XOR_QUAD_CurrentVersionRun_9815 {
  strings:
    $key_9815 = { cb 7a [2] ef 74 [2] c4 58 [2] ea 7a [2] fe 61 [2] f1 7b [2] ef 66 [2] ed 67 [2] f6 61 [2] ea 66 [2] f6 49 }

  condition:
    any of them
}