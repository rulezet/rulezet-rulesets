rule TTP_XOR_MULT_DOSStub_0d5c {
  strings:
    $key_0d5c = { 59 34 [2] 2d 2c [2] 6a 2e [2] 2d 3f [2] 63 33 [2] 6f 39 [2] 78 32 [2] 63 7c [2] 5e }

  condition:
    any of them
}