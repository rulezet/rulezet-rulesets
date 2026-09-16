rule TTP_XOR_MULT_DOSStub_c154 {
  strings:
    $key_c154 = { 95 3c [2] e1 24 [2] a6 26 [2] e1 37 [2] af 3b [2] a3 31 [2] b4 3a [2] af 74 [2] 92 }

  condition:
    any of them
}