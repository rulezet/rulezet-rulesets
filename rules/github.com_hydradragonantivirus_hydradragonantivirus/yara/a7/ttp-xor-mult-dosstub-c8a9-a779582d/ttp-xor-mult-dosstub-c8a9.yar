rule TTP_XOR_MULT_DOSStub_c8a9 {
  strings:
    $key_c8a9 = { 9c c1 [2] e8 d9 [2] af db [2] e8 ca [2] a6 c6 [2] aa cc [2] bd c7 [2] a6 89 [2] 9b }

  condition:
    any of them
}