rule TTP_XOR_MULT_DOSStub_8bf0 {
  strings:
    $key_8bf0 = { df 98 [2] ab 80 [2] ec 82 [2] ab 93 [2] e5 9f [2] e9 95 [2] fe 9e [2] e5 d0 [2] d8 }

  condition:
    any of them
}