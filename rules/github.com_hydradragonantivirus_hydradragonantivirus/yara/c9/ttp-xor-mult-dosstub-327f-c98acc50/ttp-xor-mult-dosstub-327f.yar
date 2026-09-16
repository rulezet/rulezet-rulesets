rule TTP_XOR_MULT_DOSStub_327f {
  strings:
    $key_327f = { 66 17 [2] 12 0f [2] 55 0d [2] 12 1c [2] 5c 10 [2] 50 1a [2] 47 11 [2] 5c 5f [2] 61 }

  condition:
    any of them
}