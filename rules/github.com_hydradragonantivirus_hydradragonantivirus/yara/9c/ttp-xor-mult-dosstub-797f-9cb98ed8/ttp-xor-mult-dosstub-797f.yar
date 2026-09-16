rule TTP_XOR_MULT_DOSStub_797f {
  strings:
    $key_797f = { 2d 17 [2] 59 0f [2] 1e 0d [2] 59 1c [2] 17 10 [2] 1b 1a [2] 0c 11 [2] 17 5f [2] 2a }

  condition:
    any of them
}