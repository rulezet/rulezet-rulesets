rule TTP_XOR_MULT_DOSStub_205c {
  strings:
    $key_205c = { 74 34 [2] 00 2c [2] 47 2e [2] 00 3f [2] 4e 33 [2] 42 39 [2] 55 32 [2] 4e 7c [2] 73 }

  condition:
    any of them
}