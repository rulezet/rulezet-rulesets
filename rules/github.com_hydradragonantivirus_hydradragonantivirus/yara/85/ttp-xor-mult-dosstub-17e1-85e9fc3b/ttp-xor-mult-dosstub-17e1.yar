rule TTP_XOR_MULT_DOSStub_17e1 {
  strings:
    $key_17e1 = { 43 89 [2] 37 91 [2] 70 93 [2] 37 82 [2] 79 8e [2] 75 84 [2] 62 8f [2] 79 c1 [2] 44 }

  condition:
    any of them
}