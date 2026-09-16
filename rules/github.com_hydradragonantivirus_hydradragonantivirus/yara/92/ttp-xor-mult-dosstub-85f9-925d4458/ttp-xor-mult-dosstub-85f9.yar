rule TTP_XOR_MULT_DOSStub_85f9 {
  strings:
    $key_85f9 = { d1 91 [2] a5 89 [2] e2 8b [2] a5 9a [2] eb 96 [2] e7 9c [2] f0 97 [2] eb d9 [2] d6 }

  condition:
    any of them
}