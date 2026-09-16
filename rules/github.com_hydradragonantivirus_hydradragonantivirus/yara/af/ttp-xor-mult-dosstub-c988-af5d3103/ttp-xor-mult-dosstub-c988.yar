rule TTP_XOR_MULT_DOSStub_c988 {
  strings:
    $key_c988 = { 9d e0 [2] e9 f8 [2] ae fa [2] e9 eb [2] a7 e7 [2] ab ed [2] bc e6 [2] a7 a8 [2] 9a }

  condition:
    any of them
}