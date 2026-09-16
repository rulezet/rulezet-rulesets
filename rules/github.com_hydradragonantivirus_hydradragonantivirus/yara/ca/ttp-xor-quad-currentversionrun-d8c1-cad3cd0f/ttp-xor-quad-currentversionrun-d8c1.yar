rule TTP_XOR_QUAD_CurrentVersionRun_d8c1 {
  strings:
    $key_d8c1 = { 8b ae [2] af a0 [2] 84 8c [2] aa ae [2] be b5 [2] b1 af [2] af b2 [2] ad b3 [2] b6 b5 [2] aa b2 [2] b6 9d }

  condition:
    any of them
}