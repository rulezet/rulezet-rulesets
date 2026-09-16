rule TTP_XOR_MULT_DOSStub_016f {
  strings:
    $key_016f = { 55 07 [2] 21 1f [2] 66 1d [2] 21 0c [2] 6f 00 [2] 63 0a [2] 74 01 [2] 6f 4f [2] 52 }

  condition:
    any of them
}