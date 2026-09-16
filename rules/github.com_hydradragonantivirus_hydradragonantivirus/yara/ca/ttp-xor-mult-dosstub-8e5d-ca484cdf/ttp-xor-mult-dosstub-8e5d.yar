rule TTP_XOR_MULT_DOSStub_8e5d {
  strings:
    $key_8e5d = { da 35 [2] ae 2d [2] e9 2f [2] ae 3e [2] e0 32 [2] ec 38 [2] fb 33 [2] e0 7d [2] dd }

  condition:
    any of them
}