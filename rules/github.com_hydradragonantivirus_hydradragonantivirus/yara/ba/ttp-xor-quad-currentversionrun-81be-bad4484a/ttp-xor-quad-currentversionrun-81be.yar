rule TTP_XOR_QUAD_CurrentVersionRun_81be {
  strings:
    $key_81be = { d2 d1 [2] f6 df [2] dd f3 [2] f3 d1 [2] e7 ca [2] e8 d0 [2] f6 cd [2] f4 cc [2] ef ca [2] f3 cd [2] ef e2 }

  condition:
    any of them
}