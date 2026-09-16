rule TTP_XOR_MULT_DOSStub_8e32 {
  strings:
    $key_8e32 = { da 5a [2] ae 42 [2] e9 40 [2] ae 51 [2] e0 5d [2] ec 57 [2] fb 5c [2] e0 12 [2] dd }

  condition:
    any of them
}