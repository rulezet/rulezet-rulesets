rule TTP_XOR_MULT_DOSStub_8e55 {
  strings:
    $key_8e55 = { da 3d [2] ae 25 [2] e9 27 [2] ae 36 [2] e0 3a [2] ec 30 [2] fb 3b [2] e0 75 [2] dd }

  condition:
    any of them
}