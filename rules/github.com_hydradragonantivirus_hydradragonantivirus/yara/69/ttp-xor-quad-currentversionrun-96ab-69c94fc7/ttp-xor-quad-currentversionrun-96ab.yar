rule TTP_XOR_QUAD_CurrentVersionRun_96ab {
  strings:
    $key_96ab = { c5 c4 [2] e1 ca [2] ca e6 [2] e4 c4 [2] f0 df [2] ff c5 [2] e1 d8 [2] e3 d9 [2] f8 df [2] e4 d8 [2] f8 f7 }

  condition:
    any of them
}