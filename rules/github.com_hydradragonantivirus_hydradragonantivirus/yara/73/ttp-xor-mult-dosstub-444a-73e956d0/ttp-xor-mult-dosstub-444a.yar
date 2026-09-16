rule TTP_XOR_MULT_DOSStub_444a {
  strings:
    $key_444a = { 10 22 [2] 64 3a [2] 23 38 [2] 64 29 [2] 2a 25 [2] 26 2f [2] 31 24 [2] 2a 6a [2] 17 }

  condition:
    any of them
}