rule TTP_XOR_MULT_DOSStub_376f {
  strings:
    $key_376f = { 63 07 [2] 17 1f [2] 50 1d [2] 17 0c [2] 59 00 [2] 55 0a [2] 42 01 [2] 59 4f [2] 64 }

  condition:
    any of them
}