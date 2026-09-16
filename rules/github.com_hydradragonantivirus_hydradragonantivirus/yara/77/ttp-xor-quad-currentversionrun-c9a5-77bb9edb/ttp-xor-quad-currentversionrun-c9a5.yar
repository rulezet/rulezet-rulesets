rule TTP_XOR_QUAD_CurrentVersionRun_c9a5 {
  strings:
    $key_c9a5 = { 9a ca [2] be c4 [2] 95 e8 [2] bb ca [2] af d1 [2] a0 cb [2] be d6 [2] bc d7 [2] a7 d1 [2] bb d6 [2] a7 f9 }

  condition:
    any of them
}