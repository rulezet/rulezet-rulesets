rule TTP_XOR_MULT_DOSStub_4b5c {
  strings:
    $key_4b5c = { 1f 34 [2] 6b 2c [2] 2c 2e [2] 6b 3f [2] 25 33 [2] 29 39 [2] 3e 32 [2] 25 7c [2] 18 }

  condition:
    any of them
}