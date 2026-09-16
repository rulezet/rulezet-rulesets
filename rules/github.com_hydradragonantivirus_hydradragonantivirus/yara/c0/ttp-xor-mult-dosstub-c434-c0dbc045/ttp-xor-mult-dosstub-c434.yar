rule TTP_XOR_MULT_DOSStub_c434 {
  strings:
    $key_c434 = { 90 5c [2] e4 44 [2] a3 46 [2] e4 57 [2] aa 5b [2] a6 51 [2] b1 5a [2] aa 14 [2] 97 }

  condition:
    any of them
}