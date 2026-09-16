rule TTP_XOR_QUAD_CurrentVersionRun_9814 {
  strings:
    $key_9814 = { cb 7b [2] ef 75 [2] c4 59 [2] ea 7b [2] fe 60 [2] f1 7a [2] ef 67 [2] ed 66 [2] f6 60 [2] ea 67 [2] f6 48 }

  condition:
    any of them
}