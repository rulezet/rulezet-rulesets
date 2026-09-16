rule TTP_XOR_MULT_DOSStub_8476 {
  strings:
    $key_8476 = { d0 1e [2] a4 06 [2] e3 04 [2] a4 15 [2] ea 19 [2] e6 13 [2] f1 18 [2] ea 56 [2] d7 }

  condition:
    any of them
}