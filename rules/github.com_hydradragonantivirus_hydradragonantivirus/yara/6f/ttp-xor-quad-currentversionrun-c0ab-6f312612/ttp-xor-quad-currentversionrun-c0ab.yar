rule TTP_XOR_QUAD_CurrentVersionRun_c0ab {
  strings:
    $key_c0ab = { 93 c4 [2] b7 ca [2] 9c e6 [2] b2 c4 [2] a6 df [2] a9 c5 [2] b7 d8 [2] b5 d9 [2] ae df [2] b2 d8 [2] ae f7 }

  condition:
    any of them
}