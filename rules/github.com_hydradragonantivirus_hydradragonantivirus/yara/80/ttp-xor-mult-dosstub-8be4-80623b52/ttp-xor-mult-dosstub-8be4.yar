rule TTP_XOR_MULT_DOSStub_8be4 {
  strings:
    $key_8be4 = { df 8c [2] ab 94 [2] ec 96 [2] ab 87 [2] e5 8b [2] e9 81 [2] fe 8a [2] e5 c4 [2] d8 }

  condition:
    any of them
}