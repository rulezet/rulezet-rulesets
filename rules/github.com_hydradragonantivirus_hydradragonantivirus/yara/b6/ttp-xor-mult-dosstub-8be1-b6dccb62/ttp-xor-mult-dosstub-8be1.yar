rule TTP_XOR_MULT_DOSStub_8be1 {
  strings:
    $key_8be1 = { df 89 [2] ab 91 [2] ec 93 [2] ab 82 [2] e5 8e [2] e9 84 [2] fe 8f [2] e5 c1 [2] d8 }

  condition:
    any of them
}