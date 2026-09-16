rule TTP_XOR_QUAD_CurrentVersionRun_f4ab {
  strings:
    $key_f4ab = { a7 c4 [2] 83 ca [2] a8 e6 [2] 86 c4 [2] 92 df [2] 9d c5 [2] 83 d8 [2] 81 d9 [2] 9a df [2] 86 d8 [2] 9a f7 }

  condition:
    any of them
}