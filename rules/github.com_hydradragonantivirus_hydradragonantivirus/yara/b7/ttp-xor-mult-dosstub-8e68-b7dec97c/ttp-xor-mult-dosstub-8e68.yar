rule TTP_XOR_MULT_DOSStub_8e68 {
  strings:
    $key_8e68 = { da 00 [2] ae 18 [2] e9 1a [2] ae 0b [2] e0 07 [2] ec 0d [2] fb 06 [2] e0 48 [2] dd }

  condition:
    any of them
}