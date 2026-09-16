rule TTP_XOR_MULT_DOSStub_8b22 {
  strings:
    $key_8b22 = { df 4a [2] ab 52 [2] ec 50 [2] ab 41 [2] e5 4d [2] e9 47 [2] fe 4c [2] e5 02 [2] d8 }

  condition:
    any of them
}