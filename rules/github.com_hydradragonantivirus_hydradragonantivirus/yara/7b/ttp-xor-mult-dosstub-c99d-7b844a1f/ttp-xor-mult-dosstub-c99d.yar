rule TTP_XOR_MULT_DOSStub_c99d {
  strings:
    $key_c99d = { 9d f5 [2] e9 ed [2] ae ef [2] e9 fe [2] a7 f2 [2] ab f8 [2] bc f3 [2] a7 bd [2] 9a }

  condition:
    any of them
}