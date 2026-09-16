rule TTP_XOR_MULT_DOSStub_505a {
  strings:
    $key_505a = { 04 32 [2] 70 2a [2] 37 28 [2] 70 39 [2] 3e 35 [2] 32 3f [2] 25 34 [2] 3e 7a [2] 03 }

  condition:
    any of them
}