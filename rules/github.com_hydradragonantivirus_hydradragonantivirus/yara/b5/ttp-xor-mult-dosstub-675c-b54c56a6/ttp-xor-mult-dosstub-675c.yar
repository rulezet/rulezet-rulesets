rule TTP_XOR_MULT_DOSStub_675c {
  strings:
    $key_675c = { 33 34 [2] 47 2c [2] 00 2e [2] 47 3f [2] 09 33 [2] 05 39 [2] 12 32 [2] 09 7c [2] 34 }

  condition:
    any of them
}