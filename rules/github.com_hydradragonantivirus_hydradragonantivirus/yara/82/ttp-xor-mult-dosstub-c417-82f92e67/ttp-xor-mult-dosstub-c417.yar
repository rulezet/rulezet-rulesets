rule TTP_XOR_MULT_DOSStub_c417 {
  strings:
    $key_c417 = { 90 7f [2] e4 67 [2] a3 65 [2] e4 74 [2] aa 78 [2] a6 72 [2] b1 79 [2] aa 37 [2] 97 }

  condition:
    any of them
}