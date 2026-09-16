rule TTP_XOR_MULT_DOSStub_8eb0 {
  strings:
    $key_8eb0 = { da d8 [2] ae c0 [2] e9 c2 [2] ae d3 [2] e0 df [2] ec d5 [2] fb de [2] e0 90 [2] dd }

  condition:
    any of them
}