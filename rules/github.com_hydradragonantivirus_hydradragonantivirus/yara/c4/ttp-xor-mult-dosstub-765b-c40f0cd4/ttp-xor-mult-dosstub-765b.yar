rule TTP_XOR_MULT_DOSStub_765b {
  strings:
    $key_765b = { 22 33 [2] 56 2b [2] 11 29 [2] 56 38 [2] 18 34 [2] 14 3e [2] 03 35 [2] 18 7b [2] 25 }

  condition:
    any of them
}