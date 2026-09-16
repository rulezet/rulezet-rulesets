rule TTP_XOR_QUAD_CurrentVersionRun_c2ab {
  strings:
    $key_c2ab = { 91 c4 [2] b5 ca [2] 9e e6 [2] b0 c4 [2] a4 df [2] ab c5 [2] b5 d8 [2] b7 d9 [2] ac df [2] b0 d8 [2] ac f7 }

  condition:
    any of them
}