rule TTP_XOR_QUAD_CurrentVersionRun_ccb8 {
  strings:
    $key_ccb8 = { 9f d7 [2] bb d9 [2] 90 f5 [2] be d7 [2] aa cc [2] a5 d6 [2] bb cb [2] b9 ca [2] a2 cc [2] be cb [2] a2 e4 }

  condition:
    any of them
}