rule TTP_XOR_MULT_DOSStub_115f {
  strings:
    $key_115f = { 45 37 [2] 31 2f [2] 76 2d [2] 31 3c [2] 7f 30 [2] 73 3a [2] 64 31 [2] 7f 7f [2] 42 }

  condition:
    any of them
}