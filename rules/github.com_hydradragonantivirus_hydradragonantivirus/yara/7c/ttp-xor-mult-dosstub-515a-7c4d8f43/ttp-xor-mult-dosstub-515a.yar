rule TTP_XOR_MULT_DOSStub_515a {
  strings:
    $key_515a = { 05 32 [2] 71 2a [2] 36 28 [2] 71 39 [2] 3f 35 [2] 33 3f [2] 24 34 [2] 3f 7a [2] 02 }

  condition:
    any of them
}