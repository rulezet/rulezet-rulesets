rule TTP_XOR_MULT_DOSStub_154f {
  strings:
    $key_154f = { 41 27 [2] 35 3f [2] 72 3d [2] 35 2c [2] 7b 20 [2] 77 2a [2] 60 21 [2] 7b 6f [2] 46 }

  condition:
    any of them
}