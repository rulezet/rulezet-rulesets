rule TTP_XOR_MULT_DOSStub_7b7a {
  strings:
    $key_7b7a = { 2f 12 [2] 5b 0a [2] 1c 08 [2] 5b 19 [2] 15 15 [2] 19 1f [2] 0e 14 [2] 15 5a [2] 28 }

  condition:
    any of them
}