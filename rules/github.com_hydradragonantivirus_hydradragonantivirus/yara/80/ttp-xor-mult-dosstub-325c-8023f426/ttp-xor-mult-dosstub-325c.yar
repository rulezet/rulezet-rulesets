rule TTP_XOR_MULT_DOSStub_325c {
  strings:
    $key_325c = { 66 34 [2] 12 2c [2] 55 2e [2] 12 3f [2] 5c 33 [2] 50 39 [2] 47 32 [2] 5c 7c [2] 61 }

  condition:
    any of them
}