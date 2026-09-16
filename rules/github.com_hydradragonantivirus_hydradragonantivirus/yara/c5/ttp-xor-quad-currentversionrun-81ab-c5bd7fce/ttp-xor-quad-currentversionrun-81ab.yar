rule TTP_XOR_QUAD_CurrentVersionRun_81ab {
  strings:
    $key_81ab = { d2 c4 [2] f6 ca [2] dd e6 [2] f3 c4 [2] e7 df [2] e8 c5 [2] f6 d8 [2] f4 d9 [2] ef df [2] f3 d8 [2] ef f7 }

  condition:
    any of them
}