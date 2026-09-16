rule TTP_XOR_QUAD_CurrentVersionRun_c9b9 {
  strings:
    $key_c9b9 = { 9a d6 [2] be d8 [2] 95 f4 [2] bb d6 [2] af cd [2] a0 d7 [2] be ca [2] bc cb [2] a7 cd [2] bb ca [2] a7 e5 }

  condition:
    any of them
}