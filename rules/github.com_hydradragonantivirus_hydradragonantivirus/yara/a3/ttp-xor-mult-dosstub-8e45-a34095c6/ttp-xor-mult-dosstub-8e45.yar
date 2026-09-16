rule TTP_XOR_MULT_DOSStub_8e45 {
  strings:
    $key_8e45 = { da 2d [2] ae 35 [2] e9 37 [2] ae 26 [2] e0 2a [2] ec 20 [2] fb 2b [2] e0 65 [2] dd }

  condition:
    any of them
}