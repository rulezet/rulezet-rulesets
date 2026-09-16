rule TTP_XOR_MULT_DOSStub_8b0e {
  strings:
    $key_8b0e = { df 66 [2] ab 7e [2] ec 7c [2] ab 6d [2] e5 61 [2] e9 6b [2] fe 60 [2] e5 2e [2] d8 }

  condition:
    any of them
}