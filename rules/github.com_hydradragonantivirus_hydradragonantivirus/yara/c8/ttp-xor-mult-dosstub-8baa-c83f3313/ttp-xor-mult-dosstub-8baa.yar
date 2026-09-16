rule TTP_XOR_MULT_DOSStub_8baa {
  strings:
    $key_8baa = { df c2 [2] ab da [2] ec d8 [2] ab c9 [2] e5 c5 [2] e9 cf [2] fe c4 [2] e5 8a [2] d8 }

  condition:
    any of them
}