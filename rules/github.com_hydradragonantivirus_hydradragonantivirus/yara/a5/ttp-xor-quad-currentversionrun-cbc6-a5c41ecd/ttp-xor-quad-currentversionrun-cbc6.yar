rule TTP_XOR_QUAD_CurrentVersionRun_cbc6 {
  strings:
    $key_cbc6 = { 98 a9 [2] bc a7 [2] 97 8b [2] b9 a9 [2] ad b2 [2] a2 a8 [2] bc b5 [2] be b4 [2] a5 b2 [2] b9 b5 [2] a5 9a }

  condition:
    any of them
}