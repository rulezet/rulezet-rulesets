rule TTP_XOR_QUAD_CurrentVersionRun_c1c0 {
  strings:
    $key_c1c0 = { 92 af [2] b6 a1 [2] 9d 8d [2] b3 af [2] a7 b4 [2] a8 ae [2] b6 b3 [2] b4 b2 [2] af b4 [2] b3 b3 [2] af 9c }

  condition:
    any of them
}