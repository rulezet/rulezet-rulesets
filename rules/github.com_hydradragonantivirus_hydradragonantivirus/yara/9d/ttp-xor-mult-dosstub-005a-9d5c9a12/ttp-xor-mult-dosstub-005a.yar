rule TTP_XOR_MULT_DOSStub_005a {
  strings:
    $key_005a = { 54 32 [2] 20 2a [2] 67 28 [2] 20 39 [2] 6e 35 [2] 62 3f [2] 75 34 [2] 6e 7a [2] 53 }

  condition:
    any of them
}