rule TTP_XOR_MULT_DOSStub_3ce6 {
  strings:
    $key_3ce6 = { 68 8e [2] 1c 96 [2] 5b 94 [2] 1c 85 [2] 52 89 [2] 5e 83 [2] 49 88 [2] 52 c6 [2] 6f }

  condition:
    any of them
}