rule TTP_XOR_MULT_DOSStub_495a {
  strings:
    $key_495a = { 1d 32 [2] 69 2a [2] 2e 28 [2] 69 39 [2] 27 35 [2] 2b 3f [2] 3c 34 [2] 27 7a [2] 1a }

  condition:
    any of them
}