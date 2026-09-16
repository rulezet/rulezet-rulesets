rule TTP_XOR_MULT_DOSStub_605c {
  strings:
    $key_605c = { 34 34 [2] 40 2c [2] 07 2e [2] 40 3f [2] 0e 33 [2] 02 39 [2] 15 32 [2] 0e 7c [2] 33 }

  condition:
    any of them
}