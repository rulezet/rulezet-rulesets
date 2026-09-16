rule TTP_XOR_MULT_DOSStub_305b {
  strings:
    $key_305b = { 64 33 [2] 10 2b [2] 57 29 [2] 10 38 [2] 5e 34 [2] 52 3e [2] 45 35 [2] 5e 7b [2] 63 }

  condition:
    any of them
}