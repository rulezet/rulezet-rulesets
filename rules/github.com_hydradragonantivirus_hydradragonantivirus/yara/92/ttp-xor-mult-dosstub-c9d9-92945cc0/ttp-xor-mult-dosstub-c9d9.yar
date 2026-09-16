rule TTP_XOR_MULT_DOSStub_c9d9 {
  strings:
    $key_c9d9 = { 9d b1 [2] e9 a9 [2] ae ab [2] e9 ba [2] a7 b6 [2] ab bc [2] bc b7 [2] a7 f9 [2] 9a }

  condition:
    any of them
}