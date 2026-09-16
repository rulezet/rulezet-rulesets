rule TTP_XOR_MULT_DOSStub_c438 {
  strings:
    $key_c438 = { 90 50 [2] e4 48 [2] a3 4a [2] e4 5b [2] aa 57 [2] a6 5d [2] b1 56 [2] aa 18 [2] 97 }

  condition:
    any of them
}