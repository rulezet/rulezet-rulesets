rule TTP_XOR_MULT_DOSStub_705f {
  strings:
    $key_705f = { 24 37 [2] 50 2f [2] 17 2d [2] 50 3c [2] 1e 30 [2] 12 3a [2] 05 31 [2] 1e 7f [2] 23 }

  condition:
    any of them
}