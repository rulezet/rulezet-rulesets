rule TTP_XOR_MULT_DOSStub_8bf2 {
  strings:
    $key_8bf2 = { df 9a [2] ab 82 [2] ec 80 [2] ab 91 [2] e5 9d [2] e9 97 [2] fe 9c [2] e5 d2 [2] d8 }

  condition:
    any of them
}