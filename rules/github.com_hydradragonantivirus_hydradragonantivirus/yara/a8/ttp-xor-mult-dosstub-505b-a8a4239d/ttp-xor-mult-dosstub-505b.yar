rule TTP_XOR_MULT_DOSStub_505b {
  strings:
    $key_505b = { 04 33 [2] 70 2b [2] 37 29 [2] 70 38 [2] 3e 34 [2] 32 3e [2] 25 35 [2] 3e 7b [2] 03 }

  condition:
    any of them
}