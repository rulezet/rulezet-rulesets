rule TTP_XOR_MULT_DOSStub_397a {
  strings:
    $key_397a = { 6d 12 [2] 19 0a [2] 5e 08 [2] 19 19 [2] 57 15 [2] 5b 1f [2] 4c 14 [2] 57 5a [2] 6a }

  condition:
    any of them
}