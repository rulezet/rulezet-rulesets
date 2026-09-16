rule TTP_XOR_MULT_DOSStub_15f0 {
  strings:
    $key_15f0 = { 41 98 [2] 35 80 [2] 72 82 [2] 35 93 [2] 7b 9f [2] 77 95 [2] 60 9e [2] 7b d0 [2] 46 }

  condition:
    any of them
}