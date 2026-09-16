rule TTP_XOR_MULT_DOSStub_8e08 {
  strings:
    $key_8e08 = { da 60 [2] ae 78 [2] e9 7a [2] ae 6b [2] e0 67 [2] ec 6d [2] fb 66 [2] e0 28 [2] dd }

  condition:
    any of them
}