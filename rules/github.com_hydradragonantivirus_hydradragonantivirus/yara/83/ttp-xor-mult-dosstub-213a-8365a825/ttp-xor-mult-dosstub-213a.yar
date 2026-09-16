rule TTP_XOR_MULT_DOSStub_213a {
  strings:
    $key_213a = { 75 52 [2] 01 4a [2] 46 48 [2] 01 59 [2] 4f 55 [2] 43 5f [2] 54 54 [2] 4f 1a [2] 72 }

  condition:
    any of them
}