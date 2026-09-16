rule TTP_XOR_MULT_DOSStub_1be0 {
  strings:
    $key_1be0 = { 4f 88 [2] 3b 90 [2] 7c 92 [2] 3b 83 [2] 75 8f [2] 79 85 [2] 6e 8e [2] 75 c0 [2] 48 }

  condition:
    any of them
}