rule TTP_XOR_MULT_DOSStub_2b00 {
  strings:
    $key_2b00 = { 7f 68 [2] 0b 70 [2] 4c 72 [2] 0b 63 [2] 45 6f [2] 49 65 [2] 5e 6e [2] 45 20 [2] 78 }

  condition:
    any of them
}