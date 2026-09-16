rule TTP_XOR_MULT_DOSStub_49fc {
  strings:
    $key_49fc = { 1d 94 [2] 69 8c [2] 2e 8e [2] 69 9f [2] 27 93 [2] 2b 99 [2] 3c 92 [2] 27 dc [2] 1a }

  condition:
    any of them
}