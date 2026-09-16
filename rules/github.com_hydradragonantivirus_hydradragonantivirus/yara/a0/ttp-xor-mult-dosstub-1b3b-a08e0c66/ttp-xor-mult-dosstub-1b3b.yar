rule TTP_XOR_MULT_DOSStub_1b3b {
  strings:
    $key_1b3b = { 4f 53 [2] 3b 4b [2] 7c 49 [2] 3b 58 [2] 75 54 [2] 79 5e [2] 6e 55 [2] 75 1b [2] 48 }

  condition:
    any of them
}