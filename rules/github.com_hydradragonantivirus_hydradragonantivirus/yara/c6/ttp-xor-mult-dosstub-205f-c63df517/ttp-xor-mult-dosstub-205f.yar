rule TTP_XOR_MULT_DOSStub_205f {
  strings:
    $key_205f = { 74 37 [2] 00 2f [2] 47 2d [2] 00 3c [2] 4e 30 [2] 42 3a [2] 55 31 [2] 4e 7f [2] 73 }

  condition:
    any of them
}