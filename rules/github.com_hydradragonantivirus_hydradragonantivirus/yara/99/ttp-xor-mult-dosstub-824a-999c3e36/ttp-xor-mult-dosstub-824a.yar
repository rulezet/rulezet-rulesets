rule TTP_XOR_MULT_DOSStub_824a {
  strings:
    $key_824a = { d6 22 [2] a2 3a [2] e5 38 [2] a2 29 [2] ec 25 [2] e0 2f [2] f7 24 [2] ec 6a [2] d1 }

  condition:
    any of them
}