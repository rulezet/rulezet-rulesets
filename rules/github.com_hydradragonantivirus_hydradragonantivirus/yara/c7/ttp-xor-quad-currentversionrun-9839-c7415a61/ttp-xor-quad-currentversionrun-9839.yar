rule TTP_XOR_QUAD_CurrentVersionRun_9839 {
  strings:
    $key_9839 = { cb 56 [2] ef 58 [2] c4 74 [2] ea 56 [2] fe 4d [2] f1 57 [2] ef 4a [2] ed 4b [2] f6 4d [2] ea 4a [2] f6 65 }

  condition:
    any of them
}