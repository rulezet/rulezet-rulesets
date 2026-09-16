rule TTP_XOR_MULT_DOSStub_8b36 {
  strings:
    $key_8b36 = { df 5e [2] ab 46 [2] ec 44 [2] ab 55 [2] e5 59 [2] e9 53 [2] fe 58 [2] e5 16 [2] d8 }

  condition:
    any of them
}