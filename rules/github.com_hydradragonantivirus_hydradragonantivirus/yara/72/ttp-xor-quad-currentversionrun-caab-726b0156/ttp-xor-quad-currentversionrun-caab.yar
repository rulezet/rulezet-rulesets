rule TTP_XOR_QUAD_CurrentVersionRun_caab {
  strings:
    $key_caab = { 99 c4 [2] bd ca [2] 96 e6 [2] b8 c4 [2] ac df [2] a3 c5 [2] bd d8 [2] bf d9 [2] a4 df [2] b8 d8 [2] a4 f7 }

  condition:
    any of them
}