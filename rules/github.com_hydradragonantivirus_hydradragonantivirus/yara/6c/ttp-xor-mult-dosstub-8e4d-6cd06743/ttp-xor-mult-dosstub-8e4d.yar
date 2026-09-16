rule TTP_XOR_MULT_DOSStub_8e4d {
  strings:
    $key_8e4d = { da 25 [2] ae 3d [2] e9 3f [2] ae 2e [2] e0 22 [2] ec 28 [2] fb 23 [2] e0 6d [2] dd }

  condition:
    any of them
}