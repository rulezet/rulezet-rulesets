rule TTP_XOR_QUAD_CurrentVersionRun_9826 {
  strings:
    $key_9826 = { cb 49 [2] ef 47 [2] c4 6b [2] ea 49 [2] fe 52 [2] f1 48 [2] ef 55 [2] ed 54 [2] f6 52 [2] ea 55 [2] f6 7a }

  condition:
    any of them
}