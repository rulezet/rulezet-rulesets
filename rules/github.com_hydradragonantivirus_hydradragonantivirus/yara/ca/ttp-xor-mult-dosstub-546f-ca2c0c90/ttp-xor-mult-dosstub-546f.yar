rule TTP_XOR_MULT_DOSStub_546f {
  strings:
    $key_546f = { 00 07 [2] 74 1f [2] 33 1d [2] 74 0c [2] 3a 00 [2] 36 0a [2] 21 01 [2] 3a 4f [2] 07 }

  condition:
    any of them
}