rule TTP_XOR_MULT_DOSStub_1e50 {
  strings:
    $key_1e50 = { 4a 38 [2] 3e 20 [2] 79 22 [2] 3e 33 [2] 70 3f [2] 7c 35 [2] 6b 3e [2] 70 70 [2] 4d }

  condition:
    any of them
}