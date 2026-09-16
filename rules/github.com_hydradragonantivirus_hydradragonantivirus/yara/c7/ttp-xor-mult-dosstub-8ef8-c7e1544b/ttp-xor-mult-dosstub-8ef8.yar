rule TTP_XOR_MULT_DOSStub_8ef8 {
  strings:
    $key_8ef8 = { da 90 [2] ae 88 [2] e9 8a [2] ae 9b [2] e0 97 [2] ec 9d [2] fb 96 [2] e0 d8 [2] dd }

  condition:
    any of them
}