rule TTP_XOR_QUAD_CurrentVersionRun_c1be {
  strings:
    $key_c1be = { 92 d1 [2] b6 df [2] 9d f3 [2] b3 d1 [2] a7 ca [2] a8 d0 [2] b6 cd [2] b4 cc [2] af ca [2] b3 cd [2] af e2 }

  condition:
    any of them
}