rule TTP_XOR_MULT_DOSStub_2ee6 {
  strings:
    $key_2ee6 = { 7a 8e [2] 0e 96 [2] 49 94 [2] 0e 85 [2] 40 89 [2] 4c 83 [2] 5b 88 [2] 40 c6 [2] 7d }

  condition:
    any of them
}