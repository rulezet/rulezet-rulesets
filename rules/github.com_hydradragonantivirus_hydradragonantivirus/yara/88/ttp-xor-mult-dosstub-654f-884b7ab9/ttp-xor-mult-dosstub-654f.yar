rule TTP_XOR_MULT_DOSStub_654f {
  strings:
    $key_654f = { 31 27 [2] 45 3f [2] 02 3d [2] 45 2c [2] 0b 20 [2] 07 2a [2] 10 21 [2] 0b 6f [2] 36 }

  condition:
    any of them
}