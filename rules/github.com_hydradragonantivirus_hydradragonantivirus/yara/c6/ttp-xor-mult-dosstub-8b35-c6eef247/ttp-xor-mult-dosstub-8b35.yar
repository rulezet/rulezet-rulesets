rule TTP_XOR_MULT_DOSStub_8b35 {
  strings:
    $key_8b35 = { df 5d [2] ab 45 [2] ec 47 [2] ab 56 [2] e5 5a [2] e9 50 [2] fe 5b [2] e5 15 [2] d8 }

  condition:
    any of them
}