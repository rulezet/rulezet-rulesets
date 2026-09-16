rule TTP_XOR_MULT_DOSStub_c118 {
  strings:
    $key_c118 = { 95 70 [2] e1 68 [2] a6 6a [2] e1 7b [2] af 77 [2] a3 7d [2] b4 76 [2] af 38 [2] 92 }

  condition:
    any of them
}