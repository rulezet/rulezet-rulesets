rule TTP_XOR_MULT_DOSStub_7c2c {
  strings:
    $key_7c2c = { 28 44 [2] 5c 5c [2] 1b 5e [2] 5c 4f [2] 12 43 [2] 1e 49 [2] 09 42 [2] 12 0c [2] 2f }

  condition:
    any of them
}