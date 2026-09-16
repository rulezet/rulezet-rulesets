rule TTP_XOR_MULT_DOSStub_a74a {
  strings:
    $key_a74a = { f3 22 [2] 87 3a [2] c0 38 [2] 87 29 [2] c9 25 [2] c5 2f [2] d2 24 [2] c9 6a [2] f4 }

  condition:
    any of them
}