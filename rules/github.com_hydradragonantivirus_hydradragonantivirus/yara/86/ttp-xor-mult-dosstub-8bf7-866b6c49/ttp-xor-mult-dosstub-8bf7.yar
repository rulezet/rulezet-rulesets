rule TTP_XOR_MULT_DOSStub_8bf7 {
  strings:
    $key_8bf7 = { df 9f [2] ab 87 [2] ec 85 [2] ab 94 [2] e5 98 [2] e9 92 [2] fe 99 [2] e5 d7 [2] d8 }

  condition:
    any of them
}