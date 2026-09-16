rule TTP_XOR_MULT_DOSStub_4a5a {
  strings:
    $key_4a5a = { 1e 32 [2] 6a 2a [2] 2d 28 [2] 6a 39 [2] 24 35 [2] 28 3f [2] 3f 34 [2] 24 7a [2] 19 }

  condition:
    any of them
}