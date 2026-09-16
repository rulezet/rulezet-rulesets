rule TTP_XOR_MULT_DOSStub_774a {
  strings:
    $key_774a = { 23 22 [2] 57 3a [2] 10 38 [2] 57 29 [2] 19 25 [2] 15 2f [2] 02 24 [2] 19 6a [2] 24 }

  condition:
    any of them
}