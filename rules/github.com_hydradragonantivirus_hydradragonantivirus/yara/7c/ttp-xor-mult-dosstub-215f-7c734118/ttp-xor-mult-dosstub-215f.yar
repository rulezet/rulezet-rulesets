rule TTP_XOR_MULT_DOSStub_215f {
  strings:
    $key_215f = { 75 37 [2] 01 2f [2] 46 2d [2] 01 3c [2] 4f 30 [2] 43 3a [2] 54 31 [2] 4f 7f [2] 72 }

  condition:
    any of them
}