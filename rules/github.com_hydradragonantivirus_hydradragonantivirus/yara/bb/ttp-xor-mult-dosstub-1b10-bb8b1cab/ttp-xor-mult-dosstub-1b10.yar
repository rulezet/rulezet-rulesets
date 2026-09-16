rule TTP_XOR_MULT_DOSStub_1b10 {
  strings:
    $key_1b10 = { 4f 78 [2] 3b 60 [2] 7c 62 [2] 3b 73 [2] 75 7f [2] 79 75 [2] 6e 7e [2] 75 30 [2] 48 }

  condition:
    any of them
}