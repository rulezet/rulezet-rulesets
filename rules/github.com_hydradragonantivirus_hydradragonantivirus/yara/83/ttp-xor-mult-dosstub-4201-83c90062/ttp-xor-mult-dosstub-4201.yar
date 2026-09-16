rule TTP_XOR_MULT_DOSStub_4201 {
  strings:
    $key_4201 = { 16 69 [2] 62 71 [2] 25 73 [2] 62 62 [2] 2c 6e [2] 20 64 [2] 37 6f [2] 2c 21 [2] 11 }

  condition:
    any of them
}