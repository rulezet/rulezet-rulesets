rule TTP_XOR_MULT_DOSStub_505f {
  strings:
    $key_505f = { 04 37 [2] 70 2f [2] 37 2d [2] 70 3c [2] 3e 30 [2] 32 3a [2] 25 31 [2] 3e 7f [2] 03 }

  condition:
    any of them
}