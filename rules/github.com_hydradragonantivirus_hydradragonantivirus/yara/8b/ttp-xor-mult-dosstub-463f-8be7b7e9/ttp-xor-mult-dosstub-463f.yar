rule TTP_XOR_MULT_DOSStub_463f {
  strings:
    $key_463f = { 12 57 [2] 66 4f [2] 21 4d [2] 66 5c [2] 28 50 [2] 24 5a [2] 33 51 [2] 28 1f [2] 15 }

  condition:
    any of them
}