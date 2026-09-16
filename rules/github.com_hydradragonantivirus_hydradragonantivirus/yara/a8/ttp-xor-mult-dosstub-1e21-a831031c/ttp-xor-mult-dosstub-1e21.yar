rule TTP_XOR_MULT_DOSStub_1e21 {
  strings:
    $key_1e21 = { 4a 49 [2] 3e 51 [2] 79 53 [2] 3e 42 [2] 70 4e [2] 7c 44 [2] 6b 4f [2] 70 01 [2] 4d }

  condition:
    any of them
}