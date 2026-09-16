rule TTP_XOR_QUAD_CurrentVersionRun_9eab {
  strings:
    $key_9eab = { cd c4 [2] e9 ca [2] c2 e6 [2] ec c4 [2] f8 df [2] f7 c5 [2] e9 d8 [2] eb d9 [2] f0 df [2] ec d8 [2] f0 f7 }

  condition:
    any of them
}