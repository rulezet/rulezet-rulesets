rule TTP_XOR_MULT_DOSStub_8b66 {
  strings:
    $key_8b66 = { df 0e [2] ab 16 [2] ec 14 [2] ab 05 [2] e5 09 [2] e9 03 [2] fe 08 [2] e5 46 [2] d8 }

  condition:
    any of them
}