rule TTP_XOR_MULT_DOSStub_55e1 {
  strings:
    $key_55e1 = { 01 89 [2] 75 91 [2] 32 93 [2] 75 82 [2] 3b 8e [2] 37 84 [2] 20 8f [2] 3b c1 [2] 06 }

  condition:
    any of them
}