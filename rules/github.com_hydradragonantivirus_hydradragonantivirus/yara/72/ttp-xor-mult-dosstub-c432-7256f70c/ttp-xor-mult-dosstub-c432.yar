rule TTP_XOR_MULT_DOSStub_c432 {
  strings:
    $key_c432 = { 90 5a [2] e4 42 [2] a3 40 [2] e4 51 [2] aa 5d [2] a6 57 [2] b1 5c [2] aa 12 [2] 97 }

  condition:
    any of them
}