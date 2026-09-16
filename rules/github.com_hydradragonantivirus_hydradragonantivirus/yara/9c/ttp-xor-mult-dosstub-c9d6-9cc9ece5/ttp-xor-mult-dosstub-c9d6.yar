rule TTP_XOR_MULT_DOSStub_c9d6 {
  strings:
    $key_c9d6 = { 9d be [2] e9 a6 [2] ae a4 [2] e9 b5 [2] a7 b9 [2] ab b3 [2] bc b8 [2] a7 f6 [2] 9a }

  condition:
    any of them
}