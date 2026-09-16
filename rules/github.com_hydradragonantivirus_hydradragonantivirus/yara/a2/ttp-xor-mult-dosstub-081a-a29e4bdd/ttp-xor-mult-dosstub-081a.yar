rule TTP_XOR_MULT_DOSStub_081a {
  strings:
    $key_081a = { 5c 72 [2] 28 6a [2] 6f 68 [2] 28 79 [2] 66 75 [2] 6a 7f [2] 7d 74 [2] 66 3a [2] 5b }

  condition:
    any of them
}