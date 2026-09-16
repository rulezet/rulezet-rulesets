rule TTP_XOR_MULT_DOSStub_346f {
  strings:
    $key_346f = { 60 07 [2] 14 1f [2] 53 1d [2] 14 0c [2] 5a 00 [2] 56 0a [2] 41 01 [2] 5a 4f [2] 67 }

  condition:
    any of them
}