rule TTP_XOR_MULT_DOSStub_2d5f {
  strings:
    $key_2d5f = { 79 37 [2] 0d 2f [2] 4a 2d [2] 0d 3c [2] 43 30 [2] 4f 3a [2] 58 31 [2] 43 7f [2] 7e }

  condition:
    any of them
}