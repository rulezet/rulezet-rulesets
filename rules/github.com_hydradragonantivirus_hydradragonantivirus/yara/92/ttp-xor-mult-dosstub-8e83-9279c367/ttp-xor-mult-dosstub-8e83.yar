rule TTP_XOR_MULT_DOSStub_8e83 {
  strings:
    $key_8e83 = { da eb [2] ae f3 [2] e9 f1 [2] ae e0 [2] e0 ec [2] ec e6 [2] fb ed [2] e0 a3 [2] dd }

  condition:
    any of them
}