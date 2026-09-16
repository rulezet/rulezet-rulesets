rule TTP_XOR_MULT_DOSStub_6ae6 {
  strings:
    $key_6ae6 = { 3e 8e [2] 4a 96 [2] 0d 94 [2] 4a 85 [2] 04 89 [2] 08 83 [2] 1f 88 [2] 04 c6 [2] 39 }

  condition:
    any of them
}