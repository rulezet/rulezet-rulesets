rule TTP_XOR_MULT_DOSStub_8ef5 {
  strings:
    $key_8ef5 = { da 9d [2] ae 85 [2] e9 87 [2] ae 96 [2] e0 9a [2] ec 90 [2] fb 9b [2] e0 d5 [2] dd }

  condition:
    any of them
}