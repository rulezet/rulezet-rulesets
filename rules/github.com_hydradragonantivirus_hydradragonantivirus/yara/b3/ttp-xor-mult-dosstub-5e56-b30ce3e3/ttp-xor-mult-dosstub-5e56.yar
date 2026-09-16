rule TTP_XOR_MULT_DOSStub_5e56 {
  strings:
    $key_5e56 = { 0a 3e [2] 7e 26 [2] 39 24 [2] 7e 35 [2] 30 39 [2] 3c 33 [2] 2b 38 [2] 30 76 [2] 0d }

  condition:
    any of them
}