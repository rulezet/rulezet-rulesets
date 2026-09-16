rule TTP_XOR_MULT_DOSStub_c159 {
  strings:
    $key_c159 = { 95 31 [2] e1 29 [2] a6 2b [2] e1 3a [2] af 36 [2] a3 3c [2] b4 37 [2] af 79 [2] 92 }

  condition:
    any of them
}