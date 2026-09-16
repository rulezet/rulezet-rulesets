rule TTP_XOR_MULT_DOSStub_5730 {
  strings:
    $key_5730 = { 03 58 [2] 77 40 [2] 30 42 [2] 77 53 [2] 39 5f [2] 35 55 [2] 22 5e [2] 39 10 [2] 04 }

  condition:
    any of them
}