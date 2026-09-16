rule TTP_XOR_QUAD_CurrentVersionRun_cca4 {
  strings:
    $key_cca4 = { 9f cb [2] bb c5 [2] 90 e9 [2] be cb [2] aa d0 [2] a5 ca [2] bb d7 [2] b9 d6 [2] a2 d0 [2] be d7 [2] a2 f8 }

  condition:
    any of them
}