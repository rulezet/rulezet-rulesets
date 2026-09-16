rule TTP_XOR_MULT_DOSStub_7b3a {
  strings:
    $key_7b3a = { 2f 52 [2] 5b 4a [2] 1c 48 [2] 5b 59 [2] 15 55 [2] 19 5f [2] 0e 54 [2] 15 1a [2] 28 }

  condition:
    any of them
}