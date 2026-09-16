rule TTP_XOR_MULT_DOSStub_2d7f {
  strings:
    $key_2d7f = { 79 17 [2] 0d 0f [2] 4a 0d [2] 0d 1c [2] 43 10 [2] 4f 1a [2] 58 11 [2] 43 5f [2] 7e }

  condition:
    any of them
}