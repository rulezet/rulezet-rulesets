rule TTP_XOR_MULT_DOSStub_7d5f {
  strings:
    $key_7d5f = { 29 37 [2] 5d 2f [2] 1a 2d [2] 5d 3c [2] 13 30 [2] 1f 3a [2] 08 31 [2] 13 7f [2] 2e }

  condition:
    any of them
}