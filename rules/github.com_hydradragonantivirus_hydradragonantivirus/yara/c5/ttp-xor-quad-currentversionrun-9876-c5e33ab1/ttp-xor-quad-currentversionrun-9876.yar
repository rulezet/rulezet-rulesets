rule TTP_XOR_QUAD_CurrentVersionRun_9876 {
  strings:
    $key_9876 = { cb 19 [2] ef 17 [2] c4 3b [2] ea 19 [2] fe 02 [2] f1 18 [2] ef 05 [2] ed 04 [2] f6 02 [2] ea 05 [2] f6 2a }

  condition:
    any of them
}