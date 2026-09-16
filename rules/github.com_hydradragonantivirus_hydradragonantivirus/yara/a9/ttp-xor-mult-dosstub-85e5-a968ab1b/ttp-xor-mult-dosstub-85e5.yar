rule TTP_XOR_MULT_DOSStub_85e5 {
  strings:
    $key_85e5 = { d1 8d [2] a5 95 [2] e2 97 [2] a5 86 [2] eb 8a [2] e7 80 [2] f0 8b [2] eb c5 [2] d6 }

  condition:
    any of them
}