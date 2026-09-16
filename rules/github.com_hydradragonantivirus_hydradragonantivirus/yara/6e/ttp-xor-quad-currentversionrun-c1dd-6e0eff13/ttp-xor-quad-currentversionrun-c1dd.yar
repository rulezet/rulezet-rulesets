rule TTP_XOR_QUAD_CurrentVersionRun_c1dd {
  strings:
    $key_c1dd = { 92 b2 [2] b6 bc [2] 9d 90 [2] b3 b2 [2] a7 a9 [2] a8 b3 [2] b6 ae [2] b4 af [2] af a9 [2] b3 ae [2] af 81 }

  condition:
    any of them
}