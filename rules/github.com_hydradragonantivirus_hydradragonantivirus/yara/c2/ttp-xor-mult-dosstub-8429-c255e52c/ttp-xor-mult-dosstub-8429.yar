rule TTP_XOR_MULT_DOSStub_8429 {
  strings:
    $key_8429 = { d0 41 [2] a4 59 [2] e3 5b [2] a4 4a [2] ea 46 [2] e6 4c [2] f1 47 [2] ea 09 [2] d7 }

  condition:
    any of them
}