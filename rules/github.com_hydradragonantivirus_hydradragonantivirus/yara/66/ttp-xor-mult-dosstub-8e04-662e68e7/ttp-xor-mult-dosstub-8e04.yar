rule TTP_XOR_MULT_DOSStub_8e04 {
  strings:
    $key_8e04 = { da 6c [2] ae 74 [2] e9 76 [2] ae 67 [2] e0 6b [2] ec 61 [2] fb 6a [2] e0 24 [2] dd }

  condition:
    any of them
}