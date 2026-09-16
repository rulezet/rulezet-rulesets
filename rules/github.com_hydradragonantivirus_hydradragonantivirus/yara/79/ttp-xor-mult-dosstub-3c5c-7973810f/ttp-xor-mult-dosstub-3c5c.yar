rule TTP_XOR_MULT_DOSStub_3c5c {
  strings:
    $key_3c5c = { 68 34 [2] 1c 2c [2] 5b 2e [2] 1c 3f [2] 52 33 [2] 5e 39 [2] 49 32 [2] 52 7c [2] 6f }

  condition:
    any of them
}