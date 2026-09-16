rule TTP_XOR_MULT_DOSStub_8e7e {
  strings:
    $key_8e7e = { da 16 [2] ae 0e [2] e9 0c [2] ae 1d [2] e0 11 [2] ec 1b [2] fb 10 [2] e0 5e [2] dd }

  condition:
    any of them
}