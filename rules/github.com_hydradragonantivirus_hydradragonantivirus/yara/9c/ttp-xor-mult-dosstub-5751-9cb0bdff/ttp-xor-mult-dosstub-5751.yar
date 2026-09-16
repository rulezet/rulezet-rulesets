rule TTP_XOR_MULT_DOSStub_5751 {
  strings:
    $key_5751 = { 03 39 [2] 77 21 [2] 30 23 [2] 77 32 [2] 39 3e [2] 35 34 [2] 22 3f [2] 39 71 [2] 04 }

  condition:
    any of them
}