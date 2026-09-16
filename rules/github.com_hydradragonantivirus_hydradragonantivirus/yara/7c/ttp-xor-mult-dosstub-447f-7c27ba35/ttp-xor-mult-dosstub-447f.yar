rule TTP_XOR_MULT_DOSStub_447f {
  strings:
    $key_447f = { 10 17 [2] 64 0f [2] 23 0d [2] 64 1c [2] 2a 10 [2] 26 1a [2] 31 11 [2] 2a 5f [2] 17 }

  condition:
    any of them
}