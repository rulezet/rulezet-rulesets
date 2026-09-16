rule TTP_XOR_MULT_DOSStub_8e19 {
  strings:
    $key_8e19 = { da 71 [2] ae 69 [2] e9 6b [2] ae 7a [2] e0 76 [2] ec 7c [2] fb 77 [2] e0 39 [2] dd }

  condition:
    any of them
}