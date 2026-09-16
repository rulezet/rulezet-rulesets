rule TTP_XOR_MULT_DOSStub_822a {
  strings:
    $key_822a = { d6 42 [2] a2 5a [2] e5 58 [2] a2 49 [2] ec 45 [2] e0 4f [2] f7 44 [2] ec 0a [2] d1 }

  condition:
    any of them
}