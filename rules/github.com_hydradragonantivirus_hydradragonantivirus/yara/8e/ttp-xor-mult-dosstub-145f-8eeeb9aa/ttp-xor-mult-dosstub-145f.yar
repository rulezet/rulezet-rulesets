rule TTP_XOR_MULT_DOSStub_145f {
  strings:
    $key_145f = { 40 37 [2] 34 2f [2] 73 2d [2] 34 3c [2] 7a 30 [2] 76 3a [2] 61 31 [2] 7a 7f [2] 47 }

  condition:
    any of them
}