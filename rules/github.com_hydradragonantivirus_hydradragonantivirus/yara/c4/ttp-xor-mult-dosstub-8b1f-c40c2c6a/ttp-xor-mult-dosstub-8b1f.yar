rule TTP_XOR_MULT_DOSStub_8b1f {
  strings:
    $key_8b1f = { df 77 [2] ab 6f [2] ec 6d [2] ab 7c [2] e5 70 [2] e9 7a [2] fe 71 [2] e5 3f [2] d8 }

  condition:
    any of them
}