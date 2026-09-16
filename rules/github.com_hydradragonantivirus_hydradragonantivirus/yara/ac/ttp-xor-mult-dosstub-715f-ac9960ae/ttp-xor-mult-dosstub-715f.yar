rule TTP_XOR_MULT_DOSStub_715f {
  strings:
    $key_715f = { 25 37 [2] 51 2f [2] 16 2d [2] 51 3c [2] 1f 30 [2] 13 3a [2] 04 31 [2] 1f 7f [2] 22 }

  condition:
    any of them
}