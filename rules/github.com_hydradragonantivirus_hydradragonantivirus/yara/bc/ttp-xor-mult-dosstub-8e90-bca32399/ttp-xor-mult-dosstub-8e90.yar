rule TTP_XOR_MULT_DOSStub_8e90 {
  strings:
    $key_8e90 = { da f8 [2] ae e0 [2] e9 e2 [2] ae f3 [2] e0 ff [2] ec f5 [2] fb fe [2] e0 b0 [2] dd }

  condition:
    any of them
}