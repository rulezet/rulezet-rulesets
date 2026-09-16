rule TTP_XOR_MULT_DOSStub_8bf1 {
  strings:
    $key_8bf1 = { df 99 [2] ab 81 [2] ec 83 [2] ab 92 [2] e5 9e [2] e9 94 [2] fe 9f [2] e5 d1 [2] d8 }

  condition:
    any of them
}