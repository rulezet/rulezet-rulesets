rule TTP_XOR_MULT_DOSStub_527a {
  strings:
    $key_527a = { 06 12 [2] 72 0a [2] 35 08 [2] 72 19 [2] 3c 15 [2] 30 1f [2] 27 14 [2] 3c 5a [2] 01 }

  condition:
    any of them
}