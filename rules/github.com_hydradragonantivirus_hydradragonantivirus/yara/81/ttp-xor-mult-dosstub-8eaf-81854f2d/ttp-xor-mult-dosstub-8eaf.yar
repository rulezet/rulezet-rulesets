rule TTP_XOR_MULT_DOSStub_8eaf {
  strings:
    $key_8eaf = { da c7 [2] ae df [2] e9 dd [2] ae cc [2] e0 c0 [2] ec ca [2] fb c1 [2] e0 8f [2] dd }

  condition:
    any of them
}