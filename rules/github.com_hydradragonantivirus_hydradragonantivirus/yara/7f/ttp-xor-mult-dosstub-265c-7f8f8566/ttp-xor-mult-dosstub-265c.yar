rule TTP_XOR_MULT_DOSStub_265c {
  strings:
    $key_265c = { 72 34 [2] 06 2c [2] 41 2e [2] 06 3f [2] 48 33 [2] 44 39 [2] 53 32 [2] 48 7c [2] 75 }

  condition:
    any of them
}