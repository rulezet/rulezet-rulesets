rule TTP_XOR_MULT_DOSStub_775a {
  strings:
    $key_775a = { 23 32 [2] 57 2a [2] 10 28 [2] 57 39 [2] 19 35 [2] 15 3f [2] 02 34 [2] 19 7a [2] 24 }

  condition:
    any of them
}