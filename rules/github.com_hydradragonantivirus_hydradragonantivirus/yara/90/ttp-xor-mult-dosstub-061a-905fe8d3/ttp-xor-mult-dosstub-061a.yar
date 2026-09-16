rule TTP_XOR_MULT_DOSStub_061a {
  strings:
    $key_061a = { 52 72 [2] 26 6a [2] 61 68 [2] 26 79 [2] 68 75 [2] 64 7f [2] 73 74 [2] 68 3a [2] 55 }

  condition:
    any of them
}