rule TTP_XOR_MULT_DOSStub_525f {
  strings:
    $key_525f = { 06 37 [2] 72 2f [2] 35 2d [2] 72 3c [2] 3c 30 [2] 30 3a [2] 27 31 [2] 3c 7f [2] 01 }

  condition:
    any of them
}