rule TTP_XOR_MULT_DOSStub_8e3a {
  strings:
    $key_8e3a = { da 52 [2] ae 4a [2] e9 48 [2] ae 59 [2] e0 55 [2] ec 5f [2] fb 54 [2] e0 1a [2] dd }

  condition:
    any of them
}