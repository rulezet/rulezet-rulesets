rule TTP_XOR_MULT_DOSStub_bcae {
  strings:
    $key_bcae = { e8 c6 [2] 9c de [2] db dc [2] 9c cd [2] d2 c1 [2] de cb [2] c9 c0 [2] d2 8e [2] ef }

  condition:
    any of them
}