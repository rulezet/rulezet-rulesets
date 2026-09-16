rule TTP_XOR_QUAD_CurrentVersionRun_9881 {
  strings:
    $key_9881 = { cb ee [2] ef e0 [2] c4 cc [2] ea ee [2] fe f5 [2] f1 ef [2] ef f2 [2] ed f3 [2] f6 f5 [2] ea f2 [2] f6 dd }

  condition:
    any of them
}