rule TTP_XOR_MULT_DOSStub_c408 {
  strings:
    $key_c408 = { 90 60 [2] e4 78 [2] a3 7a [2] e4 6b [2] aa 67 [2] a6 6d [2] b1 66 [2] aa 28 [2] 97 }

  condition:
    any of them
}