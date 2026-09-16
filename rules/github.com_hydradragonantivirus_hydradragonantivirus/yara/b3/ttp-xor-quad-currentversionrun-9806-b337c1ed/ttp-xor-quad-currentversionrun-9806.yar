rule TTP_XOR_QUAD_CurrentVersionRun_9806 {
  strings:
    $key_9806 = { cb 69 [2] ef 67 [2] c4 4b [2] ea 69 [2] fe 72 [2] f1 68 [2] ef 75 [2] ed 74 [2] f6 72 [2] ea 75 [2] f6 5a }

  condition:
    any of them
}