rule TTP_XOR_MULT_DOSStub_c172 {
  strings:
    $key_c172 = { 95 1a [2] e1 02 [2] a6 00 [2] e1 11 [2] af 1d [2] a3 17 [2] b4 1c [2] af 52 [2] 92 }

  condition:
    any of them
}