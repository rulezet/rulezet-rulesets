rule TTP_XOR_MULT_DOSStub_8b51 {
  strings:
    $key_8b51 = { df 39 [2] ab 21 [2] ec 23 [2] ab 32 [2] e5 3e [2] e9 34 [2] fe 3f [2] e5 71 [2] d8 }

  condition:
    any of them
}