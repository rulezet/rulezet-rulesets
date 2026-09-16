rule TTP_XOR_QUAD_CurrentVersionRun_8fab {
  strings:
    $key_8fab = { dc c4 [2] f8 ca [2] d3 e6 [2] fd c4 [2] e9 df [2] e6 c5 [2] f8 d8 [2] fa d9 [2] e1 df [2] fd d8 [2] e1 f7 }

  condition:
    any of them
}