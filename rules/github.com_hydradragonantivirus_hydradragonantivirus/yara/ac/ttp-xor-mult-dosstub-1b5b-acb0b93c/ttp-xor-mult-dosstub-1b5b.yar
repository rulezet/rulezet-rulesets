rule TTP_XOR_MULT_DOSStub_1b5b {
  strings:
    $key_1b5b = { 4f 33 [2] 3b 2b [2] 7c 29 [2] 3b 38 [2] 75 34 [2] 79 3e [2] 6e 35 [2] 75 7b [2] 48 }

  condition:
    any of them
}