rule TTP_XOR_MULT_DOSStub_a73a {
  strings:
    $key_a73a = { f3 52 [2] 87 4a [2] c0 48 [2] 87 59 [2] c9 55 [2] c5 5f [2] d2 54 [2] c9 1a [2] f4 }

  condition:
    any of them
}