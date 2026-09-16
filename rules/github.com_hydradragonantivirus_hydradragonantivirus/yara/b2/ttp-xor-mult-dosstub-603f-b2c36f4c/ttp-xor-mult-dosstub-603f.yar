rule TTP_XOR_MULT_DOSStub_603f {
  strings:
    $key_603f = { 34 57 [2] 40 4f [2] 07 4d [2] 40 5c [2] 0e 50 [2] 02 5a [2] 15 51 [2] 0e 1f [2] 33 }

  condition:
    any of them
}