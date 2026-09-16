rule TTP_XOR_MULT_DOSStub_1d5c {
  strings:
    $key_1d5c = { 49 34 [2] 3d 2c [2] 7a 2e [2] 3d 3f [2] 73 33 [2] 7f 39 [2] 68 32 [2] 73 7c [2] 4e }

  condition:
    any of them
}