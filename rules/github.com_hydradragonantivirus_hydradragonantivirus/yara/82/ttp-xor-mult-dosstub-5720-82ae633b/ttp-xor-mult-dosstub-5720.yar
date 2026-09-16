rule TTP_XOR_MULT_DOSStub_5720 {
  strings:
    $key_5720 = { 03 48 [2] 77 50 [2] 30 52 [2] 77 43 [2] 39 4f [2] 35 45 [2] 22 4e [2] 39 00 [2] 04 }

  condition:
    any of them
}