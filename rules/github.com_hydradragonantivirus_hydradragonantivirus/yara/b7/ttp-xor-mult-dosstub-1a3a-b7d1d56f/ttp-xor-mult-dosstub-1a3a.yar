rule TTP_XOR_MULT_DOSStub_1a3a {
  strings:
    $key_1a3a = { 4e 52 [2] 3a 4a [2] 7d 48 [2] 3a 59 [2] 74 55 [2] 78 5f [2] 6f 54 [2] 74 1a [2] 49 }

  condition:
    any of them
}