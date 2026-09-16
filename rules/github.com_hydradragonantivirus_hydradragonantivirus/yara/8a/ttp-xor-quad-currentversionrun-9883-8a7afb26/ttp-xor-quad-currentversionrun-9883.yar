rule TTP_XOR_QUAD_CurrentVersionRun_9883 {
  strings:
    $key_9883 = { cb ec [2] ef e2 [2] c4 ce [2] ea ec [2] fe f7 [2] f1 ed [2] ef f0 [2] ed f1 [2] f6 f7 [2] ea f0 [2] f6 df }

  condition:
    any of them
}