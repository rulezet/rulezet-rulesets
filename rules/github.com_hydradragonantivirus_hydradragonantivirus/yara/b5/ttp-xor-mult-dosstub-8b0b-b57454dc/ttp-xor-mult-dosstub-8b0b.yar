rule TTP_XOR_MULT_DOSStub_8b0b {
  strings:
    $key_8b0b = { df 63 [2] ab 7b [2] ec 79 [2] ab 68 [2] e5 64 [2] e9 6e [2] fe 65 [2] e5 2b [2] d8 }

  condition:
    any of them
}