rule TTP_XOR_MULT_DOSStub_0e2c {
  strings:
    $key_0e2c = { 5a 44 [2] 2e 5c [2] 69 5e [2] 2e 4f [2] 60 43 [2] 6c 49 [2] 7b 42 [2] 60 0c [2] 5d }

  condition:
    any of them
}