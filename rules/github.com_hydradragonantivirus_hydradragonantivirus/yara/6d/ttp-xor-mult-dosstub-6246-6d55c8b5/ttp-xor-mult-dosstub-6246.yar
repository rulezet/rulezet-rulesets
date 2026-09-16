rule TTP_XOR_MULT_DOSStub_6246 {
  strings:
    $key_6246 = { 36 2e [2] 42 36 [2] 05 34 [2] 42 25 [2] 0c 29 [2] 00 23 [2] 17 28 [2] 0c 66 [2] 31 }

  condition:
    any of them
}