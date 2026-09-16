rule TTP_XOR_MULT_DOSStub_8b20 {
  strings:
    $key_8b20 = { df 48 [2] ab 50 [2] ec 52 [2] ab 43 [2] e5 4f [2] e9 45 [2] fe 4e [2] e5 00 [2] d8 }

  condition:
    any of them
}