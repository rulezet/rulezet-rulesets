rule TTP_XOR_MULT_DOSStub_355f {
  strings:
    $key_355f = { 61 37 [2] 15 2f [2] 52 2d [2] 15 3c [2] 5b 30 [2] 57 3a [2] 40 31 [2] 5b 7f [2] 66 }

  condition:
    any of them
}