rule TTP_XOR_QUAD_CurrentVersionRun_9835 {
  strings:
    $key_9835 = { cb 5a [2] ef 54 [2] c4 78 [2] ea 5a [2] fe 41 [2] f1 5b [2] ef 46 [2] ed 47 [2] f6 41 [2] ea 46 [2] f6 69 }

  condition:
    any of them
}