rule TTP_XOR_MULT_DOSStub_115c {
  strings:
    $key_115c = { 45 34 [2] 31 2c [2] 76 2e [2] 31 3f [2] 7f 33 [2] 73 39 [2] 64 32 [2] 7f 7c [2] 42 }

  condition:
    any of them
}