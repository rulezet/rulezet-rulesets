rule TTP_XOR_MULT_DOSStub_85fa {
  strings:
    $key_85fa = { d1 92 [2] a5 8a [2] e2 88 [2] a5 99 [2] eb 95 [2] e7 9f [2] f0 94 [2] eb da [2] d6 }

  condition:
    any of them
}