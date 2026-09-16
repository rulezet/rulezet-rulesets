rule TTP_XOR_MULT_DOSStub_2d6f {
  strings:
    $key_2d6f = { 79 07 [2] 0d 1f [2] 4a 1d [2] 0d 0c [2] 43 00 [2] 4f 0a [2] 58 01 [2] 43 4f [2] 7e }

  condition:
    any of them
}