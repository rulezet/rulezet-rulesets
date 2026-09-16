rule TTP_XOR_MULT_DOSStub_315f {
  strings:
    $key_315f = { 65 37 [2] 11 2f [2] 56 2d [2] 11 3c [2] 5f 30 [2] 53 3a [2] 44 31 [2] 5f 7f [2] 62 }

  condition:
    any of them
}