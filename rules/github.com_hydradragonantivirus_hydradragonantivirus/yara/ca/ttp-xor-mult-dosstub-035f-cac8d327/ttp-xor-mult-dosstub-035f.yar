rule TTP_XOR_MULT_DOSStub_035f {
  strings:
    $key_035f = { 57 37 [2] 23 2f [2] 64 2d [2] 23 3c [2] 6d 30 [2] 61 3a [2] 76 31 [2] 6d 7f [2] 50 }

  condition:
    any of them
}