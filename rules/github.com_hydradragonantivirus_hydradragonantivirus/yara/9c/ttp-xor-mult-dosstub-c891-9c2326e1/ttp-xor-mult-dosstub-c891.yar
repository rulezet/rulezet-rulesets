rule TTP_XOR_MULT_DOSStub_c891 {
  strings:
    $key_c891 = { 9c f9 [2] e8 e1 [2] af e3 [2] e8 f2 [2] a6 fe [2] aa f4 [2] bd ff [2] a6 b1 [2] 9b }

  condition:
    any of them
}