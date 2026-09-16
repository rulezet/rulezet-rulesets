rule TTP_XOR_MULT_DOSStub_8e6e {
  strings:
    $key_8e6e = { da 06 [2] ae 1e [2] e9 1c [2] ae 0d [2] e0 01 [2] ec 0b [2] fb 00 [2] e0 4e [2] dd }

  condition:
    any of them
}