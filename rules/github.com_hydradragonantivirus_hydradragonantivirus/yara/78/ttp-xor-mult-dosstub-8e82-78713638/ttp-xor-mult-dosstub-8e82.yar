rule TTP_XOR_MULT_DOSStub_8e82 {
  strings:
    $key_8e82 = { da ea [2] ae f2 [2] e9 f0 [2] ae e1 [2] e0 ed [2] ec e7 [2] fb ec [2] e0 a2 [2] dd }

  condition:
    any of them
}