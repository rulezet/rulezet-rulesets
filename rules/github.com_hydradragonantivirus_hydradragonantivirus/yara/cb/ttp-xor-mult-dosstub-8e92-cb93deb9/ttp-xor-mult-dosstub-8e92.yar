rule TTP_XOR_MULT_DOSStub_8e92 {
  strings:
    $key_8e92 = { da fa [2] ae e2 [2] e9 e0 [2] ae f1 [2] e0 fd [2] ec f7 [2] fb fc [2] e0 b2 [2] dd }

  condition:
    any of them
}