rule TTP_XOR_MULT_DOSStub_5e50 {
  strings:
    $key_5e50 = { 0a 38 [2] 7e 20 [2] 39 22 [2] 7e 33 [2] 30 3f [2] 3c 35 [2] 2b 3e [2] 30 70 [2] 0d }

  condition:
    any of them
}