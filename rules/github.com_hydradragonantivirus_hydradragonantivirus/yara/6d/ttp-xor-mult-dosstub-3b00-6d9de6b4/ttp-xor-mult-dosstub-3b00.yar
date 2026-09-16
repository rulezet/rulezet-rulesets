rule TTP_XOR_MULT_DOSStub_3b00 {
  strings:
    $key_3b00 = { 6f 68 [2] 1b 70 [2] 5c 72 [2] 1b 63 [2] 55 6f [2] 59 65 [2] 4e 6e [2] 55 20 [2] 68 }

  condition:
    any of them
}