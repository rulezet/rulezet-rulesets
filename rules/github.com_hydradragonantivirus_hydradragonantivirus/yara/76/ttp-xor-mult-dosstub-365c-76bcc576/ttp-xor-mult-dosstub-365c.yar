rule TTP_XOR_MULT_DOSStub_365c {
  strings:
    $key_365c = { 62 34 [2] 16 2c [2] 51 2e [2] 16 3f [2] 58 33 [2] 54 39 [2] 43 32 [2] 58 7c [2] 65 }

  condition:
    any of them
}