rule TTP_XOR_MULT_DOSStub_c997 {
  strings:
    $key_c997 = { 9d ff [2] e9 e7 [2] ae e5 [2] e9 f4 [2] a7 f8 [2] ab f2 [2] bc f9 [2] a7 b7 [2] 9a }

  condition:
    any of them
}