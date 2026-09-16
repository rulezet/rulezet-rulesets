rule TTP_XOR_MULT_DOSStub_c414 {
  strings:
    $key_c414 = { 90 7c [2] e4 64 [2] a3 66 [2] e4 77 [2] aa 7b [2] a6 71 [2] b1 7a [2] aa 34 [2] 97 }

  condition:
    any of them
}