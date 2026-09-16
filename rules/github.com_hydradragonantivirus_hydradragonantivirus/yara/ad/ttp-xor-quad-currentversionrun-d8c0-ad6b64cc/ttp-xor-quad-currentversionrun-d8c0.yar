rule TTP_XOR_QUAD_CurrentVersionRun_d8c0 {
  strings:
    $key_d8c0 = { 8b af [2] af a1 [2] 84 8d [2] aa af [2] be b4 [2] b1 ae [2] af b3 [2] ad b2 [2] b6 b4 [2] aa b3 [2] b6 9c }

  condition:
    any of them
}