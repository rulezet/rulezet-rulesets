rule TTP_XOR_QUAD_CurrentVersionRun_66b1 {
  strings:
    $key_66b1 = { 35 de [2] 11 d0 [2] 3a fc [2] 14 de [2] 00 c5 [2] 0f df [2] 11 c2 [2] 13 c3 [2] 08 c5 [2] 14 c2 [2] 08 ed }

  condition:
    any of them
}