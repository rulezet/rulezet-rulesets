rule TTP_XOR_MULT_DOSStub_776f {
  strings:
    $key_776f = { 23 07 [2] 57 1f [2] 10 1d [2] 57 0c [2] 19 00 [2] 15 0a [2] 02 01 [2] 19 4f [2] 24 }

  condition:
    any of them
}