rule TTP_XOR_MULT_DOSStub_104f {
  strings:
    $key_104f = { 44 27 [2] 30 3f [2] 77 3d [2] 30 2c [2] 7e 20 [2] 72 2a [2] 65 21 [2] 7e 6f [2] 43 }

  condition:
    any of them
}