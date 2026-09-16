rule TTP_XOR_QUAD_CurrentVersionRun_66ac {
  strings:
    $key_66ac = { 35 c3 [2] 11 cd [2] 3a e1 [2] 14 c3 [2] 00 d8 [2] 0f c2 [2] 11 df [2] 13 de [2] 08 d8 [2] 14 df [2] 08 f0 }

  condition:
    any of them
}