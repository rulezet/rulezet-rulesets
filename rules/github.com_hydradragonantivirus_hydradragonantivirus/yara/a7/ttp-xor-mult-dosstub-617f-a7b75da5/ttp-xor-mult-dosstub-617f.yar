rule TTP_XOR_MULT_DOSStub_617f {
  strings:
    $key_617f = { 35 17 [2] 41 0f [2] 06 0d [2] 41 1c [2] 0f 10 [2] 03 1a [2] 14 11 [2] 0f 5f [2] 32 }

  condition:
    any of them
}