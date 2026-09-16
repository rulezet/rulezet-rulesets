rule TTP_XOR_MULT_DOSStub_525c {
  strings:
    $key_525c = { 06 34 [2] 72 2c [2] 35 2e [2] 72 3f [2] 3c 33 [2] 30 39 [2] 27 32 [2] 3c 7c [2] 01 }

  condition:
    any of them
}