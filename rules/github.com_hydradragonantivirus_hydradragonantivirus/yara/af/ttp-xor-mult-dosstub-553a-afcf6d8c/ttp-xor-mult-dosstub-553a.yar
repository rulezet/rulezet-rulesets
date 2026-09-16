rule TTP_XOR_MULT_DOSStub_553a {
  strings:
    $key_553a = { 01 52 [2] 75 4a [2] 32 48 [2] 75 59 [2] 3b 55 [2] 37 5f [2] 20 54 [2] 3b 1a [2] 06 }

  condition:
    any of them
}