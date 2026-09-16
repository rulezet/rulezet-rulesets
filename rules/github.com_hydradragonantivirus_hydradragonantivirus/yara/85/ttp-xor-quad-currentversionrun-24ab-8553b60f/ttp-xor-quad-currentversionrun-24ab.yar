rule TTP_XOR_QUAD_CurrentVersionRun_24ab {
  strings:
    $key_24ab = { 77 c4 [2] 53 ca [2] 78 e6 [2] 56 c4 [2] 42 df [2] 4d c5 [2] 53 d8 [2] 51 d9 [2] 4a df [2] 56 d8 [2] 4a f7 }

  condition:
    any of them
}