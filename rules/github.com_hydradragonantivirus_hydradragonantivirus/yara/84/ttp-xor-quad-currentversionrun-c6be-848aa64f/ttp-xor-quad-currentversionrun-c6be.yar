rule TTP_XOR_QUAD_CurrentVersionRun_c6be {
  strings:
    $key_c6be = { 95 d1 [2] b1 df [2] 9a f3 [2] b4 d1 [2] a0 ca [2] af d0 [2] b1 cd [2] b3 cc [2] a8 ca [2] b4 cd [2] a8 e2 }

  condition:
    any of them
}