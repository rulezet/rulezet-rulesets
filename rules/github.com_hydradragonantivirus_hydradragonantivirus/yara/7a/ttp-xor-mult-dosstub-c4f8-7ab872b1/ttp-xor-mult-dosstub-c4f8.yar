rule TTP_XOR_MULT_DOSStub_c4f8 {
  strings:
    $key_c4f8 = { 90 90 [2] e4 88 [2] a3 8a [2] e4 9b [2] aa 97 [2] a6 9d [2] b1 96 [2] aa d8 [2] 97 }

  condition:
    any of them
}