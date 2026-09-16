rule TTP_XOR_MULT_DOSStub_8b0c {
  strings:
    $key_8b0c = { df 64 [2] ab 7c [2] ec 7e [2] ab 6f [2] e5 63 [2] e9 69 [2] fe 62 [2] e5 2c [2] d8 }

  condition:
    any of them
}