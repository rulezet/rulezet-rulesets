rule TTP_XOR_MULT_DOSStub_565c {
  strings:
    $key_565c = { 02 34 [2] 76 2c [2] 31 2e [2] 76 3f [2] 38 33 [2] 34 39 [2] 23 32 [2] 38 7c [2] 05 }

  condition:
    any of them
}