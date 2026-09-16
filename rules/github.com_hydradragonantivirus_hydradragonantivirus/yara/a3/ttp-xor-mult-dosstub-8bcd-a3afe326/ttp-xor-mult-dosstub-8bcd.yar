rule TTP_XOR_MULT_DOSStub_8bcd {
  strings:
    $key_8bcd = { df a5 [2] ab bd [2] ec bf [2] ab ae [2] e5 a2 [2] e9 a8 [2] fe a3 [2] e5 ed [2] d8 }

  condition:
    any of them
}