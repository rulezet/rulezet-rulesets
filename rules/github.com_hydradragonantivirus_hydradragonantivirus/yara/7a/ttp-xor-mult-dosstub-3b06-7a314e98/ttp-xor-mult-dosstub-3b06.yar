rule TTP_XOR_MULT_DOSStub_3b06 {
  strings:
    $key_3b06 = { 6f 6e [2] 1b 76 [2] 5c 74 [2] 1b 65 [2] 55 69 [2] 59 63 [2] 4e 68 [2] 55 26 [2] 68 }

  condition:
    any of them
}