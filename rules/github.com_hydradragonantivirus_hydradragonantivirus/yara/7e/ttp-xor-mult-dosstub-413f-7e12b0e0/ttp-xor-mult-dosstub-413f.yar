rule TTP_XOR_MULT_DOSStub_413f {
  strings:
    $key_413f = { 15 57 [2] 61 4f [2] 26 4d [2] 61 5c [2] 2f 50 [2] 23 5a [2] 34 51 [2] 2f 1f [2] 12 }

  condition:
    any of them
}