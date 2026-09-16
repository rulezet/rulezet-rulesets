rule TTP_XOR_QUAD_CurrentVersionRun_cbb9 {
  strings:
    $key_cbb9 = { 98 d6 [2] bc d8 [2] 97 f4 [2] b9 d6 [2] ad cd [2] a2 d7 [2] bc ca [2] be cb [2] a5 cd [2] b9 ca [2] a5 e5 }

  condition:
    any of them
}