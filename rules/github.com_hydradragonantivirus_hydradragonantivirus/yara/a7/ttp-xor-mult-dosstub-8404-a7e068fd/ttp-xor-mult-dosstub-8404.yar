rule TTP_XOR_MULT_DOSStub_8404 {
  strings:
    $key_8404 = { d0 6c [2] a4 74 [2] e3 76 [2] a4 67 [2] ea 6b [2] e6 61 [2] f1 6a [2] ea 24 [2] d7 }

  condition:
    any of them
}