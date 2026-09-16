rule TTP_XOR_QUAD_CurrentVersionRun_f3ab {
  strings:
    $key_f3ab = { a0 c4 [2] 84 ca [2] af e6 [2] 81 c4 [2] 95 df [2] 9a c5 [2] 84 d8 [2] 86 d9 [2] 9d df [2] 81 d8 [2] 9d f7 }

  condition:
    any of them
}