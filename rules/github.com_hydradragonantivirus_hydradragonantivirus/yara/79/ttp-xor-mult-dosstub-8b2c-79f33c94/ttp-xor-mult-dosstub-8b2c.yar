rule TTP_XOR_MULT_DOSStub_8b2c {
  strings:
    $key_8b2c = { df 44 [2] ab 5c [2] ec 5e [2] ab 4f [2] e5 43 [2] e9 49 [2] fe 42 [2] e5 0c [2] d8 }

  condition:
    any of them
}