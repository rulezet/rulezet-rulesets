rule TTP_XOR_MULT_DOSStub_c149 {
  strings:
    $key_c149 = { 95 21 [2] e1 39 [2] a6 3b [2] e1 2a [2] af 26 [2] a3 2c [2] b4 27 [2] af 69 [2] 92 }

  condition:
    any of them
}