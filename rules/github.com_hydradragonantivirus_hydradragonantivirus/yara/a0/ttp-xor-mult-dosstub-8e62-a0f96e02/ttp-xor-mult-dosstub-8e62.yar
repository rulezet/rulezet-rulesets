rule TTP_XOR_MULT_DOSStub_8e62 {
  strings:
    $key_8e62 = { da 0a [2] ae 12 [2] e9 10 [2] ae 01 [2] e0 0d [2] ec 07 [2] fb 0c [2] e0 42 [2] dd }

  condition:
    any of them
}