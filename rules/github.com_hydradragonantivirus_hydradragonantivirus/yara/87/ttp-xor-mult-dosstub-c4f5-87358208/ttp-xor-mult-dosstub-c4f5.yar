rule TTP_XOR_MULT_DOSStub_c4f5 {
  strings:
    $key_c4f5 = { 90 9d [2] e4 85 [2] a3 87 [2] e4 96 [2] aa 9a [2] a6 90 [2] b1 9b [2] aa d5 [2] 97 }

  condition:
    any of them
}