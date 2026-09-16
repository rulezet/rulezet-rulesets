rule TTP_XOR_MULT_DOSStub_354f {
  strings:
    $key_354f = { 61 27 [2] 15 3f [2] 52 3d [2] 15 2c [2] 5b 20 [2] 57 2a [2] 40 21 [2] 5b 6f [2] 66 }

  condition:
    any of them
}