rule TTP_XOR_QUAD_CurrentVersionRun_caac {
  strings:
    $key_caac = { 99 c3 [2] bd cd [2] 96 e1 [2] b8 c3 [2] ac d8 [2] a3 c2 [2] bd df [2] bf de [2] a4 d8 [2] b8 df [2] a4 f0 }

  condition:
    any of them
}