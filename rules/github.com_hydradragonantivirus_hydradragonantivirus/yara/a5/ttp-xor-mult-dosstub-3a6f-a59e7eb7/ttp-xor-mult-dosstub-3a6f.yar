rule TTP_XOR_MULT_DOSStub_3a6f {
  strings:
    $key_3a6f = { 6e 07 [2] 1a 1f [2] 5d 1d [2] 1a 0c [2] 54 00 [2] 58 0a [2] 4f 01 [2] 54 4f [2] 69 }

  condition:
    any of them
}