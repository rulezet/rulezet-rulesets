rule TTP_XOR_MULT_DOSStub_8e54 {
  strings:
    $key_8e54 = { da 3c [2] ae 24 [2] e9 26 [2] ae 37 [2] e0 3b [2] ec 31 [2] fb 3a [2] e0 74 [2] dd }

  condition:
    any of them
}