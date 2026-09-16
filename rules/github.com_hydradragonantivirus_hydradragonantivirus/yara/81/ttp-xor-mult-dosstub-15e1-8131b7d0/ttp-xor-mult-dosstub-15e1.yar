rule TTP_XOR_MULT_DOSStub_15e1 {
  strings:
    $key_15e1 = { 41 89 [2] 35 91 [2] 72 93 [2] 35 82 [2] 7b 8e [2] 77 84 [2] 60 8f [2] 7b c1 [2] 46 }

  condition:
    any of them
}