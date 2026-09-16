rule TTP_XOR_MULT_DOSStub_505c {
  strings:
    $key_505c = { 04 34 [2] 70 2c [2] 37 2e [2] 70 3f [2] 3e 33 [2] 32 39 [2] 25 32 [2] 3e 7c [2] 03 }

  condition:
    any of them
}