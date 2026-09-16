rule TTP_XOR_MULT_DOSStub_8e5e {
  strings:
    $key_8e5e = { da 36 [2] ae 2e [2] e9 2c [2] ae 3d [2] e0 31 [2] ec 3b [2] fb 30 [2] e0 7e [2] dd }

  condition:
    any of them
}