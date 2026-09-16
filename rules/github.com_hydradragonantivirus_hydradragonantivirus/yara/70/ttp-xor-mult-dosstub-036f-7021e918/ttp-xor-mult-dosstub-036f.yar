rule TTP_XOR_MULT_DOSStub_036f {
  strings:
    $key_036f = { 57 07 [2] 23 1f [2] 64 1d [2] 23 0c [2] 6d 00 [2] 61 0a [2] 76 01 [2] 6d 4f [2] 50 }

  condition:
    any of them
}