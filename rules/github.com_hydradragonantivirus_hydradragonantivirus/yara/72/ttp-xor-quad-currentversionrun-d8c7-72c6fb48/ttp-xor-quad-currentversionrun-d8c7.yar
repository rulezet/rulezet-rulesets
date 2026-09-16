rule TTP_XOR_QUAD_CurrentVersionRun_d8c7 {
  strings:
    $key_d8c7 = { 8b a8 [2] af a6 [2] 84 8a [2] aa a8 [2] be b3 [2] b1 a9 [2] af b4 [2] ad b5 [2] b6 b3 [2] aa b4 [2] b6 9b }

  condition:
    any of them
}