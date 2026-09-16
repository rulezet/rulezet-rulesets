rule TTP_XOR_MULT_DOSStub_c459 {
  strings:
    $key_c459 = { 90 31 [2] e4 29 [2] a3 2b [2] e4 3a [2] aa 36 [2] a6 3c [2] b1 37 [2] aa 79 [2] 97 }

  condition:
    any of them
}