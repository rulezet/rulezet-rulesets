rule TTP_XOR_MULT_DOSStub_336f {
  strings:
    $key_336f = { 67 07 [2] 13 1f [2] 54 1d [2] 13 0c [2] 5d 00 [2] 51 0a [2] 46 01 [2] 5d 4f [2] 60 }

  condition:
    any of them
}