rule TTP_XOR_MULT_DOSStub_1b16 {
  strings:
    $key_1b16 = { 4f 7e [2] 3b 66 [2] 7c 64 [2] 3b 75 [2] 75 79 [2] 79 73 [2] 6e 78 [2] 75 36 [2] 48 }

  condition:
    any of them
}