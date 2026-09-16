rule TTP_XOR_MULT_DOSStub_0d2c {
  strings:
    $key_0d2c = { 59 44 [2] 2d 5c [2] 6a 5e [2] 2d 4f [2] 63 43 [2] 6f 49 [2] 78 42 [2] 63 0c [2] 5e }

  condition:
    any of them
}