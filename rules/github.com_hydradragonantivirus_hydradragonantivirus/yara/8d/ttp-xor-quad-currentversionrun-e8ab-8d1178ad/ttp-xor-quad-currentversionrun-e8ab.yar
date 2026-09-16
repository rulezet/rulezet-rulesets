rule TTP_XOR_QUAD_CurrentVersionRun_e8ab {
  strings:
    $key_e8ab = { bb c4 [2] 9f ca [2] b4 e6 [2] 9a c4 [2] 8e df [2] 81 c5 [2] 9f d8 [2] 9d d9 [2] 86 df [2] 9a d8 [2] 86 f7 }

  condition:
    any of them
}