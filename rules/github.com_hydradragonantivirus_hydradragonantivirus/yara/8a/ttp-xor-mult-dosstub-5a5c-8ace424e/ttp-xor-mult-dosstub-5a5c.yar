rule TTP_XOR_MULT_DOSStub_5a5c {
  strings:
    $key_5a5c = { 0e 34 [2] 7a 2c [2] 3d 2e [2] 7a 3f [2] 34 33 [2] 38 39 [2] 2f 32 [2] 34 7c [2] 09 }

  condition:
    any of them
}