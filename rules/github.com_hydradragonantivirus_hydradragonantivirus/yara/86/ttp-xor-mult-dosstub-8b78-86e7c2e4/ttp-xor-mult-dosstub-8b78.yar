rule TTP_XOR_MULT_DOSStub_8b78 {
  strings:
    $key_8b78 = { df 10 [2] ab 08 [2] ec 0a [2] ab 1b [2] e5 17 [2] e9 1d [2] fe 16 [2] e5 58 [2] d8 }

  condition:
    any of them
}