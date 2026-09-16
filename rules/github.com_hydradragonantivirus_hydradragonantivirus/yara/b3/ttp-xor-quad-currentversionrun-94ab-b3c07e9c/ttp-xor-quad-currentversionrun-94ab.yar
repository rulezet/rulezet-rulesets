rule TTP_XOR_QUAD_CurrentVersionRun_94ab {
  strings:
    $key_94ab = { c7 c4 [2] e3 ca [2] c8 e6 [2] e6 c4 [2] f2 df [2] fd c5 [2] e3 d8 [2] e1 d9 [2] fa df [2] e6 d8 [2] fa f7 }

  condition:
    any of them
}