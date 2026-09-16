rule TTP_XOR_MULT_DOSStub_47e1 {
  strings:
    $key_47e1 = { 13 89 [2] 67 91 [2] 20 93 [2] 67 82 [2] 29 8e [2] 25 84 [2] 32 8f [2] 29 c1 [2] 14 }

  condition:
    any of them
}