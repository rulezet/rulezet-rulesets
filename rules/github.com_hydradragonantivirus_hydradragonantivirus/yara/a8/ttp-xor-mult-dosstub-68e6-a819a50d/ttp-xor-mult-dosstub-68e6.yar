rule TTP_XOR_MULT_DOSStub_68e6 {
  strings:
    $key_68e6 = { 3c 8e [2] 48 96 [2] 0f 94 [2] 48 85 [2] 06 89 [2] 0a 83 [2] 1d 88 [2] 06 c6 [2] 3b }

  condition:
    any of them
}