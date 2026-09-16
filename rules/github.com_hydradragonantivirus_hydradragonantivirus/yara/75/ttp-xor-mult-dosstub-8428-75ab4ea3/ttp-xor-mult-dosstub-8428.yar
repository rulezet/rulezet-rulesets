rule TTP_XOR_MULT_DOSStub_8428 {
  strings:
    $key_8428 = { d0 40 [2] a4 58 [2] e3 5a [2] a4 4b [2] ea 47 [2] e6 4d [2] f1 46 [2] ea 08 [2] d7 }

  condition:
    any of them
}