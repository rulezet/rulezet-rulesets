rule TTP_XOR_MULT_DOSStub_8e56 {
  strings:
    $key_8e56 = { da 3e [2] ae 26 [2] e9 24 [2] ae 35 [2] e0 39 [2] ec 33 [2] fb 38 [2] e0 76 [2] dd }

  condition:
    any of them
}