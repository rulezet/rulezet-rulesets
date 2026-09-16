rule TTP_XOR_MULT_DOSStub_5770 {
  strings:
    $key_5770 = { 03 18 [2] 77 00 [2] 30 02 [2] 77 13 [2] 39 1f [2] 35 15 [2] 22 1e [2] 39 50 [2] 04 }

  condition:
    any of them
}