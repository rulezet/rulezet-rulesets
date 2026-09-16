rule TTP_XOR_MULT_DOSStub_2be6 {
  strings:
    $key_2be6 = { 7f 8e [2] 0b 96 [2] 4c 94 [2] 0b 85 [2] 45 89 [2] 49 83 [2] 5e 88 [2] 45 c6 [2] 78 }

  condition:
    any of them
}