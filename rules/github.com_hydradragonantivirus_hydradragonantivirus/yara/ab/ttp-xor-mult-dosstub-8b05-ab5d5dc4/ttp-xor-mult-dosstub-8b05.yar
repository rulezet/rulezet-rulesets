rule TTP_XOR_MULT_DOSStub_8b05 {
  strings:
    $key_8b05 = { df 6d [2] ab 75 [2] ec 77 [2] ab 66 [2] e5 6a [2] e9 60 [2] fe 6b [2] e5 25 [2] d8 }

  condition:
    any of them
}