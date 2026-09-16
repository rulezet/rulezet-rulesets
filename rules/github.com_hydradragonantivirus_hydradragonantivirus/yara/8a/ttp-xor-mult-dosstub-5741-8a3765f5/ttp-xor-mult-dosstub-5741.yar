rule TTP_XOR_MULT_DOSStub_5741 {
  strings:
    $key_5741 = { 03 29 [2] 77 31 [2] 30 33 [2] 77 22 [2] 39 2e [2] 35 24 [2] 22 2f [2] 39 61 [2] 04 }

  condition:
    any of them
}