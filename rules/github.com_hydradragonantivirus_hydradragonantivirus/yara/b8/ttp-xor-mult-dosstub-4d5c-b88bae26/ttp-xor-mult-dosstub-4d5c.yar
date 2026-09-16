rule TTP_XOR_MULT_DOSStub_4d5c {
  strings:
    $key_4d5c = { 19 34 [2] 6d 2c [2] 2a 2e [2] 6d 3f [2] 23 33 [2] 2f 39 [2] 38 32 [2] 23 7c [2] 1e }

  condition:
    any of them
}