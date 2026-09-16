rule TTP_XOR_MULT_DOSStub_8bfa {
  strings:
    $key_8bfa = { df 92 [2] ab 8a [2] ec 88 [2] ab 99 [2] e5 95 [2] e9 9f [2] fe 94 [2] e5 da [2] d8 }

  condition:
    any of them
}