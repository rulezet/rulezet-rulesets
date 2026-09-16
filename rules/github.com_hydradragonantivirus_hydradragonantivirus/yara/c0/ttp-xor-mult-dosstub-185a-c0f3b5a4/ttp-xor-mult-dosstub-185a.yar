rule TTP_XOR_MULT_DOSStub_185a {
  strings:
    $key_185a = { 4c 32 [2] 38 2a [2] 7f 28 [2] 38 39 [2] 76 35 [2] 7a 3f [2] 6d 34 [2] 76 7a [2] 4b }

  condition:
    any of them
}