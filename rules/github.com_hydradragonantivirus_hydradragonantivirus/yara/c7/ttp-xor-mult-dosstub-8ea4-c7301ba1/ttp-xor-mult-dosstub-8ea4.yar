rule TTP_XOR_MULT_DOSStub_8ea4 {
  strings:
    $key_8ea4 = { da cc [2] ae d4 [2] e9 d6 [2] ae c7 [2] e0 cb [2] ec c1 [2] fb ca [2] e0 84 [2] dd }

  condition:
    any of them
}