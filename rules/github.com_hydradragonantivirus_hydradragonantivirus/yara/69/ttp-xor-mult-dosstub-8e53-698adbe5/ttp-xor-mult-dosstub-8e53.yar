rule TTP_XOR_MULT_DOSStub_8e53 {
  strings:
    $key_8e53 = { da 3b [2] ae 23 [2] e9 21 [2] ae 30 [2] e0 3c [2] ec 36 [2] fb 3d [2] e0 73 [2] dd }

  condition:
    any of them
}