rule TTP_XOR_MULT_DOSStub_704a {
  strings:
    $key_704a = { 24 22 [2] 50 3a [2] 17 38 [2] 50 29 [2] 1e 25 [2] 12 2f [2] 05 24 [2] 1e 6a [2] 23 }

  condition:
    any of them
}