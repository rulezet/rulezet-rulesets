rule TTP_XOR_MULT_DOSStub_645a {
  strings:
    $key_645a = { 30 32 [2] 44 2a [2] 03 28 [2] 44 39 [2] 0a 35 [2] 06 3f [2] 11 34 [2] 0a 7a [2] 37 }

  condition:
    any of them
}