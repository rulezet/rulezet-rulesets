rule TTP_XOR_MULT_DOSStub_492f {
  strings:
    $key_492f = { 1d 47 [2] 69 5f [2] 2e 5d [2] 69 4c [2] 27 40 [2] 2b 4a [2] 3c 41 [2] 27 0f [2] 1a }

  condition:
    any of them
}