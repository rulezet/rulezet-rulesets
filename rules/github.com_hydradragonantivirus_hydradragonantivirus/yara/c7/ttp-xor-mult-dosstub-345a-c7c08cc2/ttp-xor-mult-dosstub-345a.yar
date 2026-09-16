rule TTP_XOR_MULT_DOSStub_345a {
  strings:
    $key_345a = { 60 32 [2] 14 2a [2] 53 28 [2] 14 39 [2] 5a 35 [2] 56 3f [2] 41 34 [2] 5a 7a [2] 67 }

  condition:
    any of them
}