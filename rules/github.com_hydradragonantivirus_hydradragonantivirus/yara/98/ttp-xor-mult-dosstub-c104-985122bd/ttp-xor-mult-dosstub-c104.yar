rule TTP_XOR_MULT_DOSStub_c104 {
  strings:
    $key_c104 = { 95 6c [2] e1 74 [2] a6 76 [2] e1 67 [2] af 6b [2] a3 61 [2] b4 6a [2] af 24 [2] 92 }

  condition:
    any of them
}