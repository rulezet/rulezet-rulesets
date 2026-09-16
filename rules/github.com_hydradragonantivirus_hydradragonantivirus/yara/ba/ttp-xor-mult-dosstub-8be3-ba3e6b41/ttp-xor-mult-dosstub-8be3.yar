rule TTP_XOR_MULT_DOSStub_8be3 {
  strings:
    $key_8be3 = { df 8b [2] ab 93 [2] ec 91 [2] ab 80 [2] e5 8c [2] e9 86 [2] fe 8d [2] e5 c3 [2] d8 }

  condition:
    any of them
}