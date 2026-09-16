rule TTP_XOR_MULT_DOSStub_385c {
  strings:
    $key_385c = { 6c 34 [2] 18 2c [2] 5f 2e [2] 18 3f [2] 56 33 [2] 5a 39 [2] 4d 32 [2] 56 7c [2] 6b }

  condition:
    any of them
}