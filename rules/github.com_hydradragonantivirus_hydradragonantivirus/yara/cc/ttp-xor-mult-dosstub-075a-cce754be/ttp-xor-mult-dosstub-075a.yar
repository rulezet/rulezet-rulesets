rule TTP_XOR_MULT_DOSStub_075a {
  strings:
    $key_075a = { 53 32 [2] 27 2a [2] 60 28 [2] 27 39 [2] 69 35 [2] 65 3f [2] 72 34 [2] 69 7a [2] 54 }

  condition:
    any of them
}