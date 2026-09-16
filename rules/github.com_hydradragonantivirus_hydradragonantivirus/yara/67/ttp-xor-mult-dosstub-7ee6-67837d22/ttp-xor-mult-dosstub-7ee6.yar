rule TTP_XOR_MULT_DOSStub_7ee6 {
  strings:
    $key_7ee6 = { 2a 8e [2] 5e 96 [2] 19 94 [2] 5e 85 [2] 10 89 [2] 1c 83 [2] 0b 88 [2] 10 c6 [2] 2d }

  condition:
    any of them
}