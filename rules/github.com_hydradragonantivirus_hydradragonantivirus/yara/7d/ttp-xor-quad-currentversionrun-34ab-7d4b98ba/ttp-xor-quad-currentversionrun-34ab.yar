rule TTP_XOR_QUAD_CurrentVersionRun_34ab {
  strings:
    $key_34ab = { 67 c4 [2] 43 ca [2] 68 e6 [2] 46 c4 [2] 52 df [2] 5d c5 [2] 43 d8 [2] 41 d9 [2] 5a df [2] 46 d8 [2] 5a f7 }

  condition:
    any of them
}