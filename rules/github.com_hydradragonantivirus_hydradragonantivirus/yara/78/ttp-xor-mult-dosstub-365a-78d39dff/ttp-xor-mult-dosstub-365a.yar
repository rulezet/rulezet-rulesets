rule TTP_XOR_MULT_DOSStub_365a {
  strings:
    $key_365a = { 62 32 [2] 16 2a [2] 51 28 [2] 16 39 [2] 58 35 [2] 54 3f [2] 43 34 [2] 58 7a [2] 65 }

  condition:
    any of them
}