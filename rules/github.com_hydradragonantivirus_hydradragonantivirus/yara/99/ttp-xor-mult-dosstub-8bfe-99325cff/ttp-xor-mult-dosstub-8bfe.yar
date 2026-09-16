rule TTP_XOR_MULT_DOSStub_8bfe {
  strings:
    $key_8bfe = { df 96 [2] ab 8e [2] ec 8c [2] ab 9d [2] e5 91 [2] e9 9b [2] fe 90 [2] e5 de [2] d8 }

  condition:
    any of them
}