rule TTP_XOR_MULT_DOSStub_1e27 {
  strings:
    $key_1e27 = { 4a 4f [2] 3e 57 [2] 79 55 [2] 3e 44 [2] 70 48 [2] 7c 42 [2] 6b 49 [2] 70 07 [2] 4d }

  condition:
    any of them
}