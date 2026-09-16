rule TTP_XOR_MULT_DOSStub_8e86 {
  strings:
    $key_8e86 = { da ee [2] ae f6 [2] e9 f4 [2] ae e5 [2] e0 e9 [2] ec e3 [2] fb e8 [2] e0 a6 [2] dd }

  condition:
    any of them
}