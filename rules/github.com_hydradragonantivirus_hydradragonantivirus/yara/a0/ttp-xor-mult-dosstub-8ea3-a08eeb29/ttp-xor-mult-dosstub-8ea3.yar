rule TTP_XOR_MULT_DOSStub_8ea3 {
  strings:
    $key_8ea3 = { da cb [2] ae d3 [2] e9 d1 [2] ae c0 [2] e0 cc [2] ec c6 [2] fb cd [2] e0 83 [2] dd }

  condition:
    any of them
}