rule TTP_XOR_MULT_DOSStub_504a {
  strings:
    $key_504a = { 04 22 [2] 70 3a [2] 37 38 [2] 70 29 [2] 3e 25 [2] 32 2f [2] 25 24 [2] 3e 6a [2] 03 }

  condition:
    any of them
}