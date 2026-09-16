rule TTP_XOR_MULT_DOSStub_455b {
  strings:
    $key_455b = { 11 33 [2] 65 2b [2] 22 29 [2] 65 38 [2] 2b 34 [2] 27 3e [2] 30 35 [2] 2b 7b [2] 16 }

  condition:
    any of them
}