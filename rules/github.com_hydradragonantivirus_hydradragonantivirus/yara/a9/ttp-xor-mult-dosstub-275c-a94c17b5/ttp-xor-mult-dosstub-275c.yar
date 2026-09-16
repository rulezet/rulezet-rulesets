rule TTP_XOR_MULT_DOSStub_275c {
  strings:
    $key_275c = { 73 34 [2] 07 2c [2] 40 2e [2] 07 3f [2] 49 33 [2] 45 39 [2] 52 32 [2] 49 7c [2] 74 }

  condition:
    any of them
}