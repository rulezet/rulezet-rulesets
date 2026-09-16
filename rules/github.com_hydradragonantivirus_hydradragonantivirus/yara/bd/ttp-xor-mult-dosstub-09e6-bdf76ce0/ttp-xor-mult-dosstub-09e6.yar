rule TTP_XOR_MULT_DOSStub_09e6 {
  strings:
    $key_09e6 = { 5d 8e [2] 29 96 [2] 6e 94 [2] 29 85 [2] 67 89 [2] 6b 83 [2] 7c 88 [2] 67 c6 [2] 5a }

  condition:
    any of them
}