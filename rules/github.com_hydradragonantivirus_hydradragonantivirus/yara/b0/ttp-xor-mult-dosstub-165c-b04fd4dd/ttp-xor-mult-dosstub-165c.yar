rule TTP_XOR_MULT_DOSStub_165c {
  strings:
    $key_165c = { 42 34 [2] 36 2c [2] 71 2e [2] 36 3f [2] 78 33 [2] 74 39 [2] 63 32 [2] 78 7c [2] 45 }

  condition:
    any of them
}