rule TTP_XOR_MULT_DOSStub_8e7f {
  strings:
    $key_8e7f = { da 17 [2] ae 0f [2] e9 0d [2] ae 1c [2] e0 10 [2] ec 1a [2] fb 11 [2] e0 5f [2] dd }

  condition:
    any of them
}