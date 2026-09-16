rule TTP_XOR_MULT_DOSStub_8e5a {
  strings:
    $key_8e5a = { da 32 [2] ae 2a [2] e9 28 [2] ae 39 [2] e0 35 [2] ec 3f [2] fb 34 [2] e0 7a [2] dd }

  condition:
    any of them
}