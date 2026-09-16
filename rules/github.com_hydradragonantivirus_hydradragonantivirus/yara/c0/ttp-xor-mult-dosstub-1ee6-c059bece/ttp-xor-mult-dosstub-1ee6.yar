rule TTP_XOR_MULT_DOSStub_1ee6 {
  strings:
    $key_1ee6 = { 4a 8e [2] 3e 96 [2] 79 94 [2] 3e 85 [2] 70 89 [2] 7c 83 [2] 6b 88 [2] 70 c6 [2] 4d }

  condition:
    any of them
}