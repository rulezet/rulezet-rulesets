rule TTP_XOR_MULT_DOSStub_c132 {
  strings:
    $key_c132 = { 95 5a [2] e1 42 [2] a6 40 [2] e1 51 [2] af 5d [2] a3 57 [2] b4 5c [2] af 12 [2] 92 }

  condition:
    any of them
}