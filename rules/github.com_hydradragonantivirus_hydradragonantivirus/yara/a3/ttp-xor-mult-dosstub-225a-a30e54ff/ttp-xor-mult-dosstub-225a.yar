rule TTP_XOR_MULT_DOSStub_225a {
  strings:
    $key_225a = { 76 32 [2] 02 2a [2] 45 28 [2] 02 39 [2] 4c 35 [2] 40 3f [2] 57 34 [2] 4c 7a [2] 71 }

  condition:
    any of them
}