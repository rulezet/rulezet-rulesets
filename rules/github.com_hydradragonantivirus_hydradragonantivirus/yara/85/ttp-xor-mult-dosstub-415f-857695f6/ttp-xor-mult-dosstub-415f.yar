rule TTP_XOR_MULT_DOSStub_415f {
  strings:
    $key_415f = { 15 37 [2] 61 2f [2] 26 2d [2] 61 3c [2] 2f 30 [2] 23 3a [2] 34 31 [2] 2f 7f [2] 12 }

  condition:
    any of them
}