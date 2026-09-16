rule TTP_XOR_MULT_DOSStub_310a {
  strings:
    $key_310a = { 65 62 [2] 11 7a [2] 56 78 [2] 11 69 [2] 5f 65 [2] 53 6f [2] 44 64 [2] 5f 2a [2] 62 }

  condition:
    any of them
}