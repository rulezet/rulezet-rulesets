rule TTP_XOR_MULT_DOSStub_437f {
  strings:
    $key_437f = { 17 17 [2] 63 0f [2] 24 0d [2] 63 1c [2] 2d 10 [2] 21 1a [2] 36 11 [2] 2d 5f [2] 10 }

  condition:
    any of them
}