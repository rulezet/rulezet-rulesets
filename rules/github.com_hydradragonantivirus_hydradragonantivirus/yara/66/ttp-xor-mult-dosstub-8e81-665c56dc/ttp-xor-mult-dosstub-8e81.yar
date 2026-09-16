rule TTP_XOR_MULT_DOSStub_8e81 {
  strings:
    $key_8e81 = { da e9 [2] ae f1 [2] e9 f3 [2] ae e2 [2] e0 ee [2] ec e4 [2] fb ef [2] e0 a1 [2] dd }

  condition:
    any of them
}