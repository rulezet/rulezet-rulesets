rule TTP_XOR_QUAD_CurrentVersionRun_98ab {
  strings:
    $key_98ab = { cb c4 [2] ef ca [2] c4 e6 [2] ea c4 [2] fe df [2] f1 c5 [2] ef d8 [2] ed d9 [2] f6 df [2] ea d8 [2] f6 f7 }

  condition:
    any of them
}