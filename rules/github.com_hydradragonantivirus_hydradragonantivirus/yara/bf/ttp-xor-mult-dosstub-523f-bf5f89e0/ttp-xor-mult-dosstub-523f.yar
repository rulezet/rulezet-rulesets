rule TTP_XOR_MULT_DOSStub_523f {
  strings:
    $key_523f = { 06 57 [2] 72 4f [2] 35 4d [2] 72 5c [2] 3c 50 [2] 30 5a [2] 27 51 [2] 3c 1f [2] 01 }

  condition:
    any of them
}