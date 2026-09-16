rule TTP_XOR_MULT_DOSStub_781f {
  strings:
    $key_781f = { 2c 77 [2] 58 6f [2] 1f 6d [2] 58 7c [2] 16 70 [2] 1a 7a [2] 0d 71 [2] 16 3f [2] 2b }

  condition:
    any of them
}