rule TTP_XOR_MULT_DOSStub_0b11 {
  strings:
    $key_0b11 = { 5f 79 [2] 2b 61 [2] 6c 63 [2] 2b 72 [2] 65 7e [2] 69 74 [2] 7e 7f [2] 65 31 [2] 58 }

  condition:
    any of them
}