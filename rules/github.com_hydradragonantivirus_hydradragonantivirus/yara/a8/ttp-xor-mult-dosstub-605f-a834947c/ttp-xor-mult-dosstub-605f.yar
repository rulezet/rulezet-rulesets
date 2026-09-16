rule TTP_XOR_MULT_DOSStub_605f {
  strings:
    $key_605f = { 34 37 [2] 40 2f [2] 07 2d [2] 40 3c [2] 0e 30 [2] 02 3a [2] 15 31 [2] 0e 7f [2] 33 }

  condition:
    any of them
}