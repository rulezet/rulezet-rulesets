rule TTP_XOR_MULT_DOSStub_395a {
  strings:
    $key_395a = { 6d 32 [2] 19 2a [2] 5e 28 [2] 19 39 [2] 57 35 [2] 5b 3f [2] 4c 34 [2] 57 7a [2] 6a }

  condition:
    any of them
}