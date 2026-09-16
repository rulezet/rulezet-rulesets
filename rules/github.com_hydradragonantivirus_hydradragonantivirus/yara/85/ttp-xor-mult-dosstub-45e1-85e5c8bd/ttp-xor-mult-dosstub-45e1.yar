rule TTP_XOR_MULT_DOSStub_45e1 {
  strings:
    $key_45e1 = { 11 89 [2] 65 91 [2] 22 93 [2] 65 82 [2] 2b 8e [2] 27 84 [2] 30 8f [2] 2b c1 [2] 16 }

  condition:
    any of them
}