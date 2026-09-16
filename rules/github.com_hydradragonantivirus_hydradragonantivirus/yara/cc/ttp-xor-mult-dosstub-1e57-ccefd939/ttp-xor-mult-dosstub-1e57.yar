rule TTP_XOR_MULT_DOSStub_1e57 {
  strings:
    $key_1e57 = { 4a 3f [2] 3e 27 [2] 79 25 [2] 3e 34 [2] 70 38 [2] 7c 32 [2] 6b 39 [2] 70 77 [2] 4d }

  condition:
    any of them
}