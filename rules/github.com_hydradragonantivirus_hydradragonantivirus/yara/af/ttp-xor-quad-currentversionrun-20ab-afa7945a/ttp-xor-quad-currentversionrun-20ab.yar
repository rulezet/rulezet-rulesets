rule TTP_XOR_QUAD_CurrentVersionRun_20ab {
  strings:
    $key_20ab = { 73 c4 [2] 57 ca [2] 7c e6 [2] 52 c4 [2] 46 df [2] 49 c5 [2] 57 d8 [2] 55 d9 [2] 4e df [2] 52 d8 [2] 4e f7 }

  condition:
    any of them
}