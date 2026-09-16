rule TTP_XOR_MULT_DOSStub_175f {
  strings:
    $key_175f = { 43 37 [2] 37 2f [2] 70 2d [2] 37 3c [2] 79 30 [2] 75 3a [2] 62 31 [2] 79 7f [2] 44 }

  condition:
    any of them
}