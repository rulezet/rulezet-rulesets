rule TTP_XOR_QUAD_CurrentVersionRun_9866 {
  strings:
    $key_9866 = { cb 09 [2] ef 07 [2] c4 2b [2] ea 09 [2] fe 12 [2] f1 08 [2] ef 15 [2] ed 14 [2] f6 12 [2] ea 15 [2] f6 3a }

  condition:
    any of them
}