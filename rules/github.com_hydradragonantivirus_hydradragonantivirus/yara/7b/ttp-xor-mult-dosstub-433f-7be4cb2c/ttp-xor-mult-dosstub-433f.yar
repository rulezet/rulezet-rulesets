rule TTP_XOR_MULT_DOSStub_433f {
  strings:
    $key_433f = { 17 57 [2] 63 4f [2] 24 4d [2] 63 5c [2] 2d 50 [2] 21 5a [2] 36 51 [2] 2d 1f [2] 10 }

  condition:
    any of them
}