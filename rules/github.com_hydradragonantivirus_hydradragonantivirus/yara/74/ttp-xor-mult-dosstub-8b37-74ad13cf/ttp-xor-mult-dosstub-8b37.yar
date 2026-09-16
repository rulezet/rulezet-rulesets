rule TTP_XOR_MULT_DOSStub_8b37 {
  strings:
    $key_8b37 = { df 5f [2] ab 47 [2] ec 45 [2] ab 54 [2] e5 58 [2] e9 52 [2] fe 59 [2] e5 17 [2] d8 }

  condition:
    any of them
}