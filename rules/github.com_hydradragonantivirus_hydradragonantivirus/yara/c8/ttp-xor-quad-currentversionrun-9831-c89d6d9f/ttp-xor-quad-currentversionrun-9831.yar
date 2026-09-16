rule TTP_XOR_QUAD_CurrentVersionRun_9831 {
  strings:
    $key_9831 = { cb 5e [2] ef 50 [2] c4 7c [2] ea 5e [2] fe 45 [2] f1 5f [2] ef 42 [2] ed 43 [2] f6 45 [2] ea 42 [2] f6 6d }

  condition:
    any of them
}