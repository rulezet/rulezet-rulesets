rule TTP_XOR_MULT_DOSStub_743a {
  strings:
    $key_743a = { 20 52 [2] 54 4a [2] 13 48 [2] 54 59 [2] 1a 55 [2] 16 5f [2] 01 54 [2] 1a 1a [2] 27 }

  condition:
    any of them
}