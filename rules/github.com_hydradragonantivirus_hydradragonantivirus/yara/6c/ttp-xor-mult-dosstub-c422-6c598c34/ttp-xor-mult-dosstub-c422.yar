rule TTP_XOR_MULT_DOSStub_c422 {
  strings:
    $key_c422 = { 90 4a [2] e4 52 [2] a3 50 [2] e4 41 [2] aa 4d [2] a6 47 [2] b1 4c [2] aa 02 [2] 97 }

  condition:
    any of them
}