rule TTP_XOR_MULT_DOSStub_2e2c {
  strings:
    $key_2e2c = { 7a 44 [2] 0e 5c [2] 49 5e [2] 0e 4f [2] 40 43 [2] 4c 49 [2] 5b 42 [2] 40 0c [2] 7d }

  condition:
    any of them
}