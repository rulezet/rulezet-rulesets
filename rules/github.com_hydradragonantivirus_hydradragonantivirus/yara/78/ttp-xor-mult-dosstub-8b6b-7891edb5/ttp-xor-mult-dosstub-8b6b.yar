rule TTP_XOR_MULT_DOSStub_8b6b {
  strings:
    $key_8b6b = { df 03 [2] ab 1b [2] ec 19 [2] ab 08 [2] e5 04 [2] e9 0e [2] fe 05 [2] e5 4b [2] d8 }

  condition:
    any of them
}