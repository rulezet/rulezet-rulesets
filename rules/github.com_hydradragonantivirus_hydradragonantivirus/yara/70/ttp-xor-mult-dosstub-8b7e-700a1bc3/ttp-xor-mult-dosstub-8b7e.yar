rule TTP_XOR_MULT_DOSStub_8b7e {
  strings:
    $key_8b7e = { df 16 [2] ab 0e [2] ec 0c [2] ab 1d [2] e5 11 [2] e9 1b [2] fe 10 [2] e5 5e [2] d8 }

  condition:
    any of them
}