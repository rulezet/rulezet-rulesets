rule TTP_XOR_MULT_DOSStub_2a7a {
  strings:
    $key_2a7a = { 7e 12 [2] 0a 0a [2] 4d 08 [2] 0a 19 [2] 44 15 [2] 48 1f [2] 5f 14 [2] 44 5a [2] 79 }

  condition:
    any of them
}