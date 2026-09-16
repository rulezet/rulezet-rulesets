rule TTP_XOR_MULT_DOSStub_8e42 {
  strings:
    $key_8e42 = { da 2a [2] ae 32 [2] e9 30 [2] ae 21 [2] e0 2d [2] ec 27 [2] fb 2c [2] e0 62 [2] dd }

  condition:
    any of them
}