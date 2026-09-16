rule TTP_XOR_MULT_DOSStub_8ea2 {
  strings:
    $key_8ea2 = { da ca [2] ae d2 [2] e9 d0 [2] ae c1 [2] e0 cd [2] ec c7 [2] fb cc [2] e0 82 [2] dd }

  condition:
    any of them
}