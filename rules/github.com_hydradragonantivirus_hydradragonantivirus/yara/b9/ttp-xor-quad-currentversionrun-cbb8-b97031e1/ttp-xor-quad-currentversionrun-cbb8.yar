rule TTP_XOR_QUAD_CurrentVersionRun_cbb8 {
  strings:
    $key_cbb8 = { 98 d7 [2] bc d9 [2] 97 f5 [2] b9 d7 [2] ad cc [2] a2 d6 [2] bc cb [2] be ca [2] a5 cc [2] b9 cb [2] a5 e4 }

  condition:
    any of them
}