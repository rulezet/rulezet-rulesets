rule TTP_XOR_MULT_DOSStub_085c {
  strings:
    $key_085c = { 5c 34 [2] 28 2c [2] 6f 2e [2] 28 3f [2] 66 33 [2] 6a 39 [2] 7d 32 [2] 66 7c [2] 5b }

  condition:
    any of them
}