rule TTP_XOR_MULT_DOSStub_5a5f {
  strings:
    $key_5a5f = { 0e 37 [2] 7a 2f [2] 3d 2d [2] 7a 3c [2] 34 30 [2] 38 3a [2] 2f 31 [2] 34 7f [2] 09 }

  condition:
    any of them
}