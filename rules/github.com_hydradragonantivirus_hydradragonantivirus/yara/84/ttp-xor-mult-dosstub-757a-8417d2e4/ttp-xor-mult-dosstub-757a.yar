rule TTP_XOR_MULT_DOSStub_757a {
  strings:
    $key_757a = { 21 12 [2] 55 0a [2] 12 08 [2] 55 19 [2] 1b 15 [2] 17 1f [2] 00 14 [2] 1b 5a [2] 26 }

  condition:
    any of them
}