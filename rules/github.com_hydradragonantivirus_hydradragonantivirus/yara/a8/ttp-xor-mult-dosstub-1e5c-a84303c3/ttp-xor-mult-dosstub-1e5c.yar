rule TTP_XOR_MULT_DOSStub_1e5c {
  strings:
    $key_1e5c = { 4a 34 [2] 3e 2c [2] 79 2e [2] 3e 3f [2] 70 33 [2] 7c 39 [2] 6b 32 [2] 70 7c [2] 4d }

  condition:
    any of them
}