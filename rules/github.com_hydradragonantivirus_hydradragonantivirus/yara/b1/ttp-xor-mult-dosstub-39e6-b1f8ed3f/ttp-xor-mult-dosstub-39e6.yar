rule TTP_XOR_MULT_DOSStub_39e6 {
  strings:
    $key_39e6 = { 6d 8e [2] 19 96 [2] 5e 94 [2] 19 85 [2] 57 89 [2] 5b 83 [2] 4c 88 [2] 57 c6 [2] 6a }

  condition:
    any of them
}