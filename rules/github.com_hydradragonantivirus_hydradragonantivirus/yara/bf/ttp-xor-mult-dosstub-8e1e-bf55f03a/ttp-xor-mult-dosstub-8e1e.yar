rule TTP_XOR_MULT_DOSStub_8e1e {
  strings:
    $key_8e1e = { da 76 [2] ae 6e [2] e9 6c [2] ae 7d [2] e0 71 [2] ec 7b [2] fb 70 [2] e0 3e [2] dd }

  condition:
    any of them
}