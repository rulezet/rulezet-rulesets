rule TTP_XOR_MULT_DOSStub_1e30 {
  strings:
    $key_1e30 = { 4a 58 [2] 3e 40 [2] 79 42 [2] 3e 53 [2] 70 5f [2] 7c 55 [2] 6b 5e [2] 70 10 [2] 4d }

  condition:
    any of them
}