rule TTP_XOR_MULT_DOSStub_c983 {
  strings:
    $key_c983 = { 9d eb [2] e9 f3 [2] ae f1 [2] e9 e0 [2] a7 ec [2] ab e6 [2] bc ed [2] a7 a3 [2] 9a }

  condition:
    any of them
}