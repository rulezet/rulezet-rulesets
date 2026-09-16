rule TTP_XOR_MULT_DOSStub_325a {
  strings:
    $key_325a = { 66 32 [2] 12 2a [2] 55 28 [2] 12 39 [2] 5c 35 [2] 50 3f [2] 47 34 [2] 5c 7a [2] 61 }

  condition:
    any of them
}