rule TTP_XOR_MULT_DOSStub_8409 {
  strings:
    $key_8409 = { d0 61 [2] a4 79 [2] e3 7b [2] a4 6a [2] ea 66 [2] e6 6c [2] f1 67 [2] ea 29 [2] d7 }

  condition:
    any of them
}