rule TTP_XOR_MULT_DOSStub_356f {
  strings:
    $key_356f = { 61 07 [2] 15 1f [2] 52 1d [2] 15 0c [2] 5b 00 [2] 57 0a [2] 40 01 [2] 5b 4f [2] 66 }

  condition:
    any of them
}