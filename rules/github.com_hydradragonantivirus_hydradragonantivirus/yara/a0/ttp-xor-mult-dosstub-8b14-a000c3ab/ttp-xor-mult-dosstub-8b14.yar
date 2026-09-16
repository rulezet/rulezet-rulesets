rule TTP_XOR_MULT_DOSStub_8b14 {
  strings:
    $key_8b14 = { df 7c [2] ab 64 [2] ec 66 [2] ab 77 [2] e5 7b [2] e9 71 [2] fe 7a [2] e5 34 [2] d8 }

  condition:
    any of them
}