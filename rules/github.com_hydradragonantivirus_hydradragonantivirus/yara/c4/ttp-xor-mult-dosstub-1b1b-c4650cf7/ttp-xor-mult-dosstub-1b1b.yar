rule TTP_XOR_MULT_DOSStub_1b1b {
  strings:
    $key_1b1b = { 4f 73 [2] 3b 6b [2] 7c 69 [2] 3b 78 [2] 75 74 [2] 79 7e [2] 6e 75 [2] 75 3b [2] 48 }

  condition:
    any of them
}