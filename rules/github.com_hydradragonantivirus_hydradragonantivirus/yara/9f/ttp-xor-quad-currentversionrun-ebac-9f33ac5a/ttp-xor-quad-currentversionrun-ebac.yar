rule TTP_XOR_QUAD_CurrentVersionRun_ebac {
  strings:
    $key_ebac = { b8 c3 [2] 9c cd [2] b7 e1 [2] 99 c3 [2] 8d d8 [2] 82 c2 [2] 9c df [2] 9e de [2] 85 d8 [2] 99 df [2] 85 f0 }

  condition:
    any of them
}