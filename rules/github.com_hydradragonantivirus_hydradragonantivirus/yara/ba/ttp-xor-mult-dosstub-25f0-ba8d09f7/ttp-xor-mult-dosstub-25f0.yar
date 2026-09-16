rule TTP_XOR_MULT_DOSStub_25f0 {
  strings:
    $key_25f0 = { 71 98 [2] 05 80 [2] 42 82 [2] 05 93 [2] 4b 9f [2] 47 95 [2] 50 9e [2] 4b d0 [2] 76 }

  condition:
    any of them
}