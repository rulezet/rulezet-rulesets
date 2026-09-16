rule TTP_XOR_MULT_DOSStub_825a {
  strings:
    $key_825a = { d6 32 [2] a2 2a [2] e5 28 [2] a2 39 [2] ec 35 [2] e0 3f [2] f7 34 [2] ec 7a [2] d1 }

  condition:
    any of them
}