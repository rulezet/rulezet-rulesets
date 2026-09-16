rule TTP_XOR_QUAD_CurrentVersionRun_9837 {
  strings:
    $key_9837 = { cb 58 [2] ef 56 [2] c4 7a [2] ea 58 [2] fe 43 [2] f1 59 [2] ef 44 [2] ed 45 [2] f6 43 [2] ea 44 [2] f6 6b }

  condition:
    any of them
}