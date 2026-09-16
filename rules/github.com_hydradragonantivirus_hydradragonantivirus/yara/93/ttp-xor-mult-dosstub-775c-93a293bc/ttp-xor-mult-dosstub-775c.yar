rule TTP_XOR_MULT_DOSStub_775c {
  strings:
    $key_775c = { 23 34 [2] 57 2c [2] 10 2e [2] 57 3f [2] 19 33 [2] 15 39 [2] 02 32 [2] 19 7c [2] 24 }

  condition:
    any of them
}