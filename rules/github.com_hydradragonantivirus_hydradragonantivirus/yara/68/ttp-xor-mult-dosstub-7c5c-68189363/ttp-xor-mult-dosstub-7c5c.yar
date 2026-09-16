rule TTP_XOR_MULT_DOSStub_7c5c {
  strings:
    $key_7c5c = { 28 34 [2] 5c 2c [2] 1b 2e [2] 5c 3f [2] 12 33 [2] 1e 39 [2] 09 32 [2] 12 7c [2] 2f }

  condition:
    any of them
}