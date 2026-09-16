rule TTP_XOR_MULT_DOSStub_207f {
  strings:
    $key_207f = { 74 17 [2] 00 0f [2] 47 0d [2] 00 1c [2] 4e 10 [2] 42 1a [2] 55 11 [2] 4e 5f [2] 73 }

  condition:
    any of them
}