rule TTP_XOR_MULT_DOSStub_8b80 {
  strings:
    $key_8b80 = { df e8 [2] ab f0 [2] ec f2 [2] ab e3 [2] e5 ef [2] e9 e5 [2] fe ee [2] e5 a0 [2] d8 }

  condition:
    any of them
}