rule TTP_XOR_MULT_DOSStub_8b2b {
  strings:
    $key_8b2b = { df 43 [2] ab 5b [2] ec 59 [2] ab 48 [2] e5 44 [2] e9 4e [2] fe 45 [2] e5 0b [2] d8 }

  condition:
    any of them
}