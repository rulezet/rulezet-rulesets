rule TTP_XOR_MULT_DOSStub_564f {
  strings:
    $key_564f = { 02 27 [2] 76 3f [2] 31 3d [2] 76 2c [2] 38 20 [2] 34 2a [2] 23 21 [2] 38 6f [2] 05 }

  condition:
    any of them
}