rule TTP_XOR_MULT_DOSStub_311a {
  strings:
    $key_311a = { 65 72 [2] 11 6a [2] 56 68 [2] 11 79 [2] 5f 75 [2] 53 7f [2] 44 74 [2] 5f 3a [2] 62 }

  condition:
    any of them
}