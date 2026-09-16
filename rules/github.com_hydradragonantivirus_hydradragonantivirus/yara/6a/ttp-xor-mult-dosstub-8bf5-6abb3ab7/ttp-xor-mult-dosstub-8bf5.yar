rule TTP_XOR_MULT_DOSStub_8bf5 {
  strings:
    $key_8bf5 = { df 9d [2] ab 85 [2] ec 87 [2] ab 96 [2] e5 9a [2] e9 90 [2] fe 9b [2] e5 d5 [2] d8 }

  condition:
    any of them
}