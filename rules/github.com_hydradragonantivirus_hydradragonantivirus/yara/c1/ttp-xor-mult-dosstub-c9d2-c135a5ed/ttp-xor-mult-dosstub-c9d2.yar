rule TTP_XOR_MULT_DOSStub_c9d2 {
  strings:
    $key_c9d2 = { 9d ba [2] e9 a2 [2] ae a0 [2] e9 b1 [2] a7 bd [2] ab b7 [2] bc bc [2] a7 f2 [2] 9a }

  condition:
    any of them
}