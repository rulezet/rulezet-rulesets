rule TTP_XOR_MULT_DOSStub_8b28 {
  strings:
    $key_8b28 = { df 40 [2] ab 58 [2] ec 5a [2] ab 4b [2] e5 47 [2] e9 4d [2] fe 46 [2] e5 08 [2] d8 }

  condition:
    any of them
}