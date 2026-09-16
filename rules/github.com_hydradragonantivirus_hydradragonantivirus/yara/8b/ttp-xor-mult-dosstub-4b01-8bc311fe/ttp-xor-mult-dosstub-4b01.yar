rule TTP_XOR_MULT_DOSStub_4b01 {
  strings:
    $key_4b01 = { 1f 69 [2] 6b 71 [2] 2c 73 [2] 6b 62 [2] 25 6e [2] 29 64 [2] 3e 6f [2] 25 21 [2] 18 }

  condition:
    any of them
}