rule TTP_XOR_QUAD_CurrentVersionRun_9dab {
  strings:
    $key_9dab = { ce c4 [2] ea ca [2] c1 e6 [2] ef c4 [2] fb df [2] f4 c5 [2] ea d8 [2] e8 d9 [2] f3 df [2] ef d8 [2] f3 f7 }

  condition:
    any of them
}