rule TTP_XOR_MULT_DOSStub_555b {
  strings:
    $key_555b = { 01 33 [2] 75 2b [2] 32 29 [2] 75 38 [2] 3b 34 [2] 37 3e [2] 20 35 [2] 3b 7b [2] 06 }

  condition:
    any of them
}