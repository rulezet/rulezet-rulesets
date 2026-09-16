rule TTP_XOR_MULT_DOSStub_215c {
  strings:
    $key_215c = { 75 34 [2] 01 2c [2] 46 2e [2] 01 3f [2] 4f 33 [2] 43 39 [2] 54 32 [2] 4f 7c [2] 72 }

  condition:
    any of them
}