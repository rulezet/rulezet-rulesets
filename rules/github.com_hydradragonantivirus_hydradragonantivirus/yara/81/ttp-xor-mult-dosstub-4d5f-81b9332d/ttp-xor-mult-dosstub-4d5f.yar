rule TTP_XOR_MULT_DOSStub_4d5f {
  strings:
    $key_4d5f = { 19 37 [2] 6d 2f [2] 2a 2d [2] 6d 3c [2] 23 30 [2] 2f 3a [2] 38 31 [2] 23 7f [2] 1e }

  condition:
    any of them
}