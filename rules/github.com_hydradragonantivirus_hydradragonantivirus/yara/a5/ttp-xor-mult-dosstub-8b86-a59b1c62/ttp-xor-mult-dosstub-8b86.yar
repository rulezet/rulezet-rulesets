rule TTP_XOR_MULT_DOSStub_8b86 {
  strings:
    $key_8b86 = { df ee [2] ab f6 [2] ec f4 [2] ab e5 [2] e5 e9 [2] e9 e3 [2] fe e8 [2] e5 a6 [2] d8 }

  condition:
    any of them
}