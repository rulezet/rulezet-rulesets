rule TTP_XOR_MULT_DOSStub_445a {
  strings:
    $key_445a = { 10 32 [2] 64 2a [2] 23 28 [2] 64 39 [2] 2a 35 [2] 26 3f [2] 31 34 [2] 2a 7a [2] 17 }

  condition:
    any of them
}