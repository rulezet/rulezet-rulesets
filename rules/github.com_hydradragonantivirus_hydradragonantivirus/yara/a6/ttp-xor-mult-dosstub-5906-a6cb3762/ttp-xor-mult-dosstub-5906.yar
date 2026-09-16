rule TTP_XOR_MULT_DOSStub_5906 {
  strings:
    $key_5906 = { 0d 6e [2] 79 76 [2] 3e 74 [2] 79 65 [2] 37 69 [2] 3b 63 [2] 2c 68 [2] 37 26 [2] 0a }

  condition:
    any of them
}