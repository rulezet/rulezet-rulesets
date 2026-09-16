rule TTP_XOR_QUAD_CurrentVersionRun_9fab {
  strings:
    $key_9fab = { cc c4 [2] e8 ca [2] c3 e6 [2] ed c4 [2] f9 df [2] f6 c5 [2] e8 d8 [2] ea d9 [2] f1 df [2] ed d8 [2] f1 f7 }

  condition:
    any of them
}