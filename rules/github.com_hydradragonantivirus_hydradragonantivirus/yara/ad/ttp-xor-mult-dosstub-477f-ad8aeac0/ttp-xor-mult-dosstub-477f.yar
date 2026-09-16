rule TTP_XOR_MULT_DOSStub_477f {
  strings:
    $key_477f = { 13 17 [2] 67 0f [2] 20 0d [2] 67 1c [2] 29 10 [2] 25 1a [2] 32 11 [2] 29 5f [2] 14 }

  condition:
    any of them
}