rule TTP_XOR_MULT_DOSStub_8b1e {
  strings:
    $key_8b1e = { df 76 [2] ab 6e [2] ec 6c [2] ab 7d [2] e5 71 [2] e9 7b [2] fe 70 [2] e5 3e [2] d8 }

  condition:
    any of them
}