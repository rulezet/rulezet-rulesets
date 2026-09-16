rule TTP_XOR_MULT_DOSStub_1b07 {
  strings:
    $key_1b07 = { 4f 6f [2] 3b 77 [2] 7c 75 [2] 3b 64 [2] 75 68 [2] 79 62 [2] 6e 69 [2] 75 27 [2] 48 }

  condition:
    any of them
}