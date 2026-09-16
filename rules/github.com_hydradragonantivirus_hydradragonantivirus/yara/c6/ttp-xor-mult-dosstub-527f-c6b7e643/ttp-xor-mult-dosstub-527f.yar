rule TTP_XOR_MULT_DOSStub_527f {
  strings:
    $key_527f = { 06 17 [2] 72 0f [2] 35 0d [2] 72 1c [2] 3c 10 [2] 30 1a [2] 27 11 [2] 3c 5f [2] 01 }

  condition:
    any of them
}