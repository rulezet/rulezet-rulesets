rule TTP_XOR_MULT_DOSStub_8bf9 {
  strings:
    $key_8bf9 = { df 91 [2] ab 89 [2] ec 8b [2] ab 9a [2] e5 96 [2] e9 9c [2] fe 97 [2] e5 d9 [2] d8 }

  condition:
    any of them
}