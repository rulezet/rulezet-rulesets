rule TTP_XOR_MULT_DOSStub_8e58 {
  strings:
    $key_8e58 = { da 30 [2] ae 28 [2] e9 2a [2] ae 3b [2] e0 37 [2] ec 3d [2] fb 36 [2] e0 78 [2] dd }

  condition:
    any of them
}