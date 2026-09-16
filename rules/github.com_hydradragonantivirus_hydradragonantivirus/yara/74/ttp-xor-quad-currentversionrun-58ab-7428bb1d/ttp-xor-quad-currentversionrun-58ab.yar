rule TTP_XOR_QUAD_CurrentVersionRun_58ab {
  strings:
    $key_58ab = { 0b c4 [2] 2f ca [2] 04 e6 [2] 2a c4 [2] 3e df [2] 31 c5 [2] 2f d8 [2] 2d d9 [2] 36 df [2] 2a d8 [2] 36 f7 }

  condition:
    any of them
}