rule TTP_XOR_MULT_DOSStub_634a {
  strings:
    $key_634a = { 37 22 [2] 43 3a [2] 04 38 [2] 43 29 [2] 0d 25 [2] 01 2f [2] 16 24 [2] 0d 6a [2] 30 }

  condition:
    any of them
}