rule TTP_XOR_QUAD_CurrentVersionRun_f8ab {
  strings:
    $key_f8ab = { ab c4 [2] 8f ca [2] a4 e6 [2] 8a c4 [2] 9e df [2] 91 c5 [2] 8f d8 [2] 8d d9 [2] 96 df [2] 8a d8 [2] 96 f7 }

  condition:
    any of them
}