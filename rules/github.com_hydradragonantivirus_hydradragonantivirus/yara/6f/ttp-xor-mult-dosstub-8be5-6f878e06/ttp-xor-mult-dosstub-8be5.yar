rule TTP_XOR_MULT_DOSStub_8be5 {
  strings:
    $key_8be5 = { df 8d [2] ab 95 [2] ec 97 [2] ab 86 [2] e5 8a [2] e9 80 [2] fe 8b [2] e5 c5 [2] d8 }

  condition:
    any of them
}