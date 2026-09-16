rule TTP_XOR_MULT_DOSStub_417f {
  strings:
    $key_417f = { 15 17 [2] 61 0f [2] 26 0d [2] 61 1c [2] 2f 10 [2] 23 1a [2] 34 11 [2] 2f 5f [2] 12 }

  condition:
    any of them
}