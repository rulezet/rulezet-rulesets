rule TTP_XOR_QUAD_CurrentVersionRun_dfab {
  strings:
    $key_dfab = { 8c c4 [2] a8 ca [2] 83 e6 [2] ad c4 [2] b9 df [2] b6 c5 [2] a8 d8 [2] aa d9 [2] b1 df [2] ad d8 [2] b1 f7 }

  condition:
    any of them
}