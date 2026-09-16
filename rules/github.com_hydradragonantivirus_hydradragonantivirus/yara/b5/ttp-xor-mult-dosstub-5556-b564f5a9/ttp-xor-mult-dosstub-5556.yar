rule TTP_XOR_MULT_DOSStub_5556 {
  strings:
    $key_5556 = { 01 3e [2] 75 26 [2] 32 24 [2] 75 35 [2] 3b 39 [2] 37 33 [2] 20 38 [2] 3b 76 [2] 06 }

  condition:
    any of them
}