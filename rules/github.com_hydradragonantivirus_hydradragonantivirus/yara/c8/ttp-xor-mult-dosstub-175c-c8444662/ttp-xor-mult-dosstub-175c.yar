rule TTP_XOR_MULT_DOSStub_175c {
  strings:
    $key_175c = { 43 34 [2] 37 2c [2] 70 2e [2] 37 3f [2] 79 33 [2] 75 39 [2] 62 32 [2] 79 7c [2] 44 }

  condition:
    any of them
}