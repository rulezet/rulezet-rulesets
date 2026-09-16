rule TTP_XOR_MULT_DOSStub_8b55 {
  strings:
    $key_8b55 = { df 3d [2] ab 25 [2] ec 27 [2] ab 36 [2] e5 3a [2] e9 30 [2] fe 3b [2] e5 75 [2] d8 }

  condition:
    any of them
}