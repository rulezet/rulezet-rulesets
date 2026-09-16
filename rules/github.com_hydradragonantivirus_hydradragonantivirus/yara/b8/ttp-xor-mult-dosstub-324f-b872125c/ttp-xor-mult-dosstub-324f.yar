rule TTP_XOR_MULT_DOSStub_324f {
  strings:
    $key_324f = { 66 27 [2] 12 3f [2] 55 3d [2] 12 2c [2] 5c 20 [2] 50 2a [2] 47 21 [2] 5c 6f [2] 61 }

  condition:
    any of them
}