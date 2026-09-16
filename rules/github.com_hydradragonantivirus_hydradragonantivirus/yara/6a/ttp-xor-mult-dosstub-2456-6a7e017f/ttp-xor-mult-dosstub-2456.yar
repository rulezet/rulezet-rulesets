rule TTP_XOR_MULT_DOSStub_2456 {
  strings:
    $key_2456 = { 70 3e [2] 04 26 [2] 43 24 [2] 04 35 [2] 4a 39 [2] 46 33 [2] 51 38 [2] 4a 76 [2] 77 }

  condition:
    any of them
}