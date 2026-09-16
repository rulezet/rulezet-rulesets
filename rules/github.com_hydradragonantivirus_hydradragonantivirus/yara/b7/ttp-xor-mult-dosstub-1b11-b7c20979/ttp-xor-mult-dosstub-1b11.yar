rule TTP_XOR_MULT_DOSStub_1b11 {
  strings:
    $key_1b11 = { 4f 79 [2] 3b 61 [2] 7c 63 [2] 3b 72 [2] 75 7e [2] 79 74 [2] 6e 7f [2] 75 31 [2] 48 }

  condition:
    any of them
}