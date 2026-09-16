rule TTP_XOR_MULT_DOSStub_8be7 {
  strings:
    $key_8be7 = { df 8f [2] ab 97 [2] ec 95 [2] ab 84 [2] e5 88 [2] e9 82 [2] fe 89 [2] e5 c7 [2] d8 }

  condition:
    any of them
}