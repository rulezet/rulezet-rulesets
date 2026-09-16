rule TTP_XOR_MULT_DOSStub_3b7a {
  strings:
    $key_3b7a = { 6f 12 [2] 1b 0a [2] 5c 08 [2] 1b 19 [2] 55 15 [2] 59 1f [2] 4e 14 [2] 55 5a [2] 68 }

  condition:
    any of them
}