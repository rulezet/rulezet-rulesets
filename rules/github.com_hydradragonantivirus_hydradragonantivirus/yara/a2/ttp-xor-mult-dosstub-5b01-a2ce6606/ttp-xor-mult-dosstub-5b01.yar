rule TTP_XOR_MULT_DOSStub_5b01 {
  strings:
    $key_5b01 = { 0f 69 [2] 7b 71 [2] 3c 73 [2] 7b 62 [2] 35 6e [2] 39 64 [2] 2e 6f [2] 35 21 [2] 08 }

  condition:
    any of them
}