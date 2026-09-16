rule TTP_XOR_MULT_DOSStub_065a {
  strings:
    $key_065a = { 52 32 [2] 26 2a [2] 61 28 [2] 26 39 [2] 68 35 [2] 64 3f [2] 73 34 [2] 68 7a [2] 55 }

  condition:
    any of them
}