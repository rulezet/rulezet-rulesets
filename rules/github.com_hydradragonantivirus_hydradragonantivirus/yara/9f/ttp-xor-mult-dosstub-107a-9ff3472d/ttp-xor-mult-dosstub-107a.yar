rule TTP_XOR_MULT_DOSStub_107a {
  strings:
    $key_107a = { 44 12 [2] 30 0a [2] 77 08 [2] 30 19 [2] 7e 15 [2] 72 1f [2] 65 14 [2] 7e 5a [2] 43 }

  condition:
    any of them
}