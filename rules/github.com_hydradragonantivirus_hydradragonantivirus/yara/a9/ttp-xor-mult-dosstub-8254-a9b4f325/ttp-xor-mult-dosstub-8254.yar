rule TTP_XOR_MULT_DOSStub_8254 {
  strings:
    $key_8254 = { d6 3c [2] a2 24 [2] e5 26 [2] a2 37 [2] ec 3b [2] e0 31 [2] f7 3a [2] ec 74 [2] d1 }

  condition:
    any of them
}