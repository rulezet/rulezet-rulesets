rule TTP_XOR_MULT_DOSStub_305c {
  strings:
    $key_305c = { 64 34 [2] 10 2c [2] 57 2e [2] 10 3f [2] 5e 33 [2] 52 39 [2] 45 32 [2] 5e 7c [2] 63 }

  condition:
    any of them
}