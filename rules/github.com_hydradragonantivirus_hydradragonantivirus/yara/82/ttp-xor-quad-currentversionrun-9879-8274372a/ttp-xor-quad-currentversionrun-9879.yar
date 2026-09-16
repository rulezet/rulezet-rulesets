rule TTP_XOR_QUAD_CurrentVersionRun_9879 {
  strings:
    $key_9879 = { cb 16 [2] ef 18 [2] c4 34 [2] ea 16 [2] fe 0d [2] f1 17 [2] ef 0a [2] ed 0b [2] f6 0d [2] ea 0a [2] f6 25 }

  condition:
    any of them
}