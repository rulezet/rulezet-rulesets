rule TTP_XOR_MULT_DOSStub_315a {
  strings:
    $key_315a = { 65 32 [2] 11 2a [2] 56 28 [2] 11 39 [2] 5f 35 [2] 53 3f [2] 44 34 [2] 5f 7a [2] 62 }

  condition:
    any of them
}