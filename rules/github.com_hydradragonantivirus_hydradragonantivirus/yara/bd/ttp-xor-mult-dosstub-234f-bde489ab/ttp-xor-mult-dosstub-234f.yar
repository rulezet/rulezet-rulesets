rule TTP_XOR_MULT_DOSStub_234f {
  strings:
    $key_234f = { 77 27 [2] 03 3f [2] 44 3d [2] 03 2c [2] 4d 20 [2] 41 2a [2] 56 21 [2] 4d 6f [2] 70 }

  condition:
    any of them
}