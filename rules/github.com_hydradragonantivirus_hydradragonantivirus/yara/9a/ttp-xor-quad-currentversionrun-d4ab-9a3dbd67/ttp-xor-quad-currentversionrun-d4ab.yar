rule TTP_XOR_QUAD_CurrentVersionRun_d4ab {
  strings:
    $key_d4ab = { 87 c4 [2] a3 ca [2] 88 e6 [2] a6 c4 [2] b2 df [2] bd c5 [2] a3 d8 [2] a1 d9 [2] ba df [2] a6 d8 [2] ba f7 }

  condition:
    any of them
}