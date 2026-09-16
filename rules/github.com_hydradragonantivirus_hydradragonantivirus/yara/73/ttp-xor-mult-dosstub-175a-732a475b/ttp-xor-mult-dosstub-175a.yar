rule TTP_XOR_MULT_DOSStub_175a {
  strings:
    $key_175a = { 43 32 [2] 37 2a [2] 70 28 [2] 37 39 [2] 79 35 [2] 75 3f [2] 62 34 [2] 79 7a [2] 44 }

  condition:
    any of them
}