rule TTP_XOR_MULT_DOSStub_5736 {
  strings:
    $key_5736 = { 03 5e [2] 77 46 [2] 30 44 [2] 77 55 [2] 39 59 [2] 35 53 [2] 22 58 [2] 39 16 [2] 04 }

  condition:
    any of them
}