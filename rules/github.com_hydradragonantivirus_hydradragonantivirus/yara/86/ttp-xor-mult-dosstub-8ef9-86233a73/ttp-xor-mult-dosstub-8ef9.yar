rule TTP_XOR_MULT_DOSStub_8ef9 {
  strings:
    $key_8ef9 = { da 91 [2] ae 89 [2] e9 8b [2] ae 9a [2] e0 96 [2] ec 9c [2] fb 97 [2] e0 d9 [2] dd }

  condition:
    any of them
}