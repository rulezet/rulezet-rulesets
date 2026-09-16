rule TTP_XOR_MULT_DOSStub_466f {
  strings:
    $key_466f = { 12 07 [2] 66 1f [2] 21 1d [2] 66 0c [2] 28 00 [2] 24 0a [2] 33 01 [2] 28 4f [2] 15 }

  condition:
    any of them
}