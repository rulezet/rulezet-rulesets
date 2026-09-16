rule TTP_XOR_MULT_DOSStub_5b3a {
  strings:
    $key_5b3a = { 0f 52 [2] 7b 4a [2] 3c 48 [2] 7b 59 [2] 35 55 [2] 39 5f [2] 2e 54 [2] 35 1a [2] 08 }

  condition:
    any of them
}