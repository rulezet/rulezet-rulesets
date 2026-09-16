rule TTP_XOR_MULT_DOSStub_3b01 {
  strings:
    $key_3b01 = { 6f 69 [2] 1b 71 [2] 5c 73 [2] 1b 62 [2] 55 6e [2] 59 64 [2] 4e 6f [2] 55 21 [2] 68 }

  condition:
    any of them
}