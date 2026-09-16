rule TTP_XOR_MULT_DOSStub_8b58 {
  strings:
    $key_8b58 = { df 30 [2] ab 28 [2] ec 2a [2] ab 3b [2] e5 37 [2] e9 3d [2] fe 36 [2] e5 78 [2] d8 }

  condition:
    any of them
}