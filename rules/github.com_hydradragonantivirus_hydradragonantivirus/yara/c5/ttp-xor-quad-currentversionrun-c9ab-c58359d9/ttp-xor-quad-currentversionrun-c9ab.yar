rule TTP_XOR_QUAD_CurrentVersionRun_c9ab {
  strings:
    $key_c9ab = { 9a c4 [2] be ca [2] 95 e6 [2] bb c4 [2] af df [2] a0 c5 [2] be d8 [2] bc d9 [2] a7 df [2] bb d8 [2] a7 f7 }

  condition:
    any of them
}