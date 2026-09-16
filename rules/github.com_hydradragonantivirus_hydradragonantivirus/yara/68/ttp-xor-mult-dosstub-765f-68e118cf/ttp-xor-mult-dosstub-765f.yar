rule TTP_XOR_MULT_DOSStub_765f {
  strings:
    $key_765f = { 22 37 [2] 56 2f [2] 11 2d [2] 56 3c [2] 18 30 [2] 14 3a [2] 03 31 [2] 18 7f [2] 25 }

  condition:
    any of them
}