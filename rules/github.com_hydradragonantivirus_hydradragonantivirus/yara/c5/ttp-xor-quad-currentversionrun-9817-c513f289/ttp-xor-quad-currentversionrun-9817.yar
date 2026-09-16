rule TTP_XOR_QUAD_CurrentVersionRun_9817 {
  strings:
    $key_9817 = { cb 78 [2] ef 76 [2] c4 5a [2] ea 78 [2] fe 63 [2] f1 79 [2] ef 64 [2] ed 65 [2] f6 63 [2] ea 64 [2] f6 4b }

  condition:
    any of them
}