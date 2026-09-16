rule TTP_XOR_MULT_DOSStub_8b1b {
  strings:
    $key_8b1b = { df 73 [2] ab 6b [2] ec 69 [2] ab 78 [2] e5 74 [2] e9 7e [2] fe 75 [2] e5 3b [2] d8 }

  condition:
    any of them
}