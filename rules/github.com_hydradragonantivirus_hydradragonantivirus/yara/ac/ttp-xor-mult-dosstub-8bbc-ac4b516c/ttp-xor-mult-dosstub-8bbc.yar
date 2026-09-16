rule TTP_XOR_MULT_DOSStub_8bbc {
  strings:
    $key_8bbc = { df d4 [2] ab cc [2] ec ce [2] ab df [2] e5 d3 [2] e9 d9 [2] fe d2 [2] e5 9c [2] d8 }

  condition:
    any of them
}