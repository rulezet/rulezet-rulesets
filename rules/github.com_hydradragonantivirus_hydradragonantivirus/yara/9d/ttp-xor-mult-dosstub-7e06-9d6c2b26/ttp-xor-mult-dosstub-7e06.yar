rule TTP_XOR_MULT_DOSStub_7e06 {
  strings:
    $key_7e06 = { 2a 6e [2] 5e 76 [2] 19 74 [2] 5e 65 [2] 10 69 [2] 1c 63 [2] 0b 68 [2] 10 26 [2] 2d }

  condition:
    any of them
}