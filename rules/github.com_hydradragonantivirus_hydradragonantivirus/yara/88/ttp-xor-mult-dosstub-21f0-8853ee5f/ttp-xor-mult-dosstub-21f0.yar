rule TTP_XOR_MULT_DOSStub_21f0 {
  strings:
    $key_21f0 = { 75 98 [2] 01 80 [2] 46 82 [2] 01 93 [2] 4f 9f [2] 43 95 [2] 54 9e [2] 4f d0 [2] 72 }

  condition:
    any of them
}