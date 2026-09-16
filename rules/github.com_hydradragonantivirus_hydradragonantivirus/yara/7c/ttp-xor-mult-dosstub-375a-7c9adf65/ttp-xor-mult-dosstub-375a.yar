rule TTP_XOR_MULT_DOSStub_375a {
  strings:
    $key_375a = { 63 32 [2] 17 2a [2] 50 28 [2] 17 39 [2] 59 35 [2] 55 3f [2] 42 34 [2] 59 7a [2] 64 }

  condition:
    any of them
}