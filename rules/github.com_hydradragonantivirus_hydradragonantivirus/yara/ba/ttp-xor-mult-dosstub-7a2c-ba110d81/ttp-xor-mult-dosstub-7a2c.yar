rule TTP_XOR_MULT_DOSStub_7a2c {
  strings:
    $key_7a2c = { 2e 44 [2] 5a 5c [2] 1d 5e [2] 5a 4f [2] 14 43 [2] 18 49 [2] 0f 42 [2] 14 0c [2] 29 }

  condition:
    any of them
}