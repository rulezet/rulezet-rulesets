rule TTP_XOR_MULT_DOSStub_355a {
  strings:
    $key_355a = { 61 32 [2] 15 2a [2] 52 28 [2] 15 39 [2] 5b 35 [2] 57 3f [2] 40 34 [2] 5b 7a [2] 66 }

  condition:
    any of them
}