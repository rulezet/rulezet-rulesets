rule TTP_XOR_MULT_DOSStub_7b16 {
  strings:
    $key_7b16 = { 2f 7e [2] 5b 66 [2] 1c 64 [2] 5b 75 [2] 15 79 [2] 19 73 [2] 0e 78 [2] 15 36 [2] 28 }

  condition:
    any of them
}