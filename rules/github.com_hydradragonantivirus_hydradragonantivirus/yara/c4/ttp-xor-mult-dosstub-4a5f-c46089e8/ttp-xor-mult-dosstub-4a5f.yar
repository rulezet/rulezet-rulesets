rule TTP_XOR_MULT_DOSStub_4a5f {
  strings:
    $key_4a5f = { 1e 37 [2] 6a 2f [2] 2d 2d [2] 6a 3c [2] 24 30 [2] 28 3a [2] 3f 31 [2] 24 7f [2] 19 }

  condition:
    any of them
}