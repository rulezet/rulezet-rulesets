rule TTP_XOR_MULT_DOSStub_845a {
  strings:
    $key_845a = { d0 32 [2] a4 2a [2] e3 28 [2] a4 39 [2] ea 35 [2] e6 3f [2] f1 34 [2] ea 7a [2] d7 }

  condition:
    any of them
}