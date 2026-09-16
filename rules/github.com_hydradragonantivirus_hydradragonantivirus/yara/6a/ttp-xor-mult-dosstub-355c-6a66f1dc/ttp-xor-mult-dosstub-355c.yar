rule TTP_XOR_MULT_DOSStub_355c {
  strings:
    $key_355c = { 61 34 [2] 15 2c [2] 52 2e [2] 15 3f [2] 5b 33 [2] 57 39 [2] 40 32 [2] 5b 7c [2] 66 }

  condition:
    any of them
}