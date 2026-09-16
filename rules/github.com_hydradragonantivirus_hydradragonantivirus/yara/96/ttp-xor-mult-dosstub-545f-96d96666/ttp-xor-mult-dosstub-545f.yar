rule TTP_XOR_MULT_DOSStub_545f {
  strings:
    $key_545f = { 00 37 [2] 74 2f [2] 33 2d [2] 74 3c [2] 3a 30 [2] 36 3a [2] 21 31 [2] 3a 7f [2] 07 }

  condition:
    any of them
}