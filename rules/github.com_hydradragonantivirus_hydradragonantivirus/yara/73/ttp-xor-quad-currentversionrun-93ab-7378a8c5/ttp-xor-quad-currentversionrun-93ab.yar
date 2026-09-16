rule TTP_XOR_QUAD_CurrentVersionRun_93ab {
  strings:
    $key_93ab = { c0 c4 [2] e4 ca [2] cf e6 [2] e1 c4 [2] f5 df [2] fa c5 [2] e4 d8 [2] e6 d9 [2] fd df [2] e1 d8 [2] fd f7 }

  condition:
    any of them
}