rule TTP_XOR_MULT_DOSStub_07e1 {
  strings:
    $key_07e1 = { 53 89 [2] 27 91 [2] 60 93 [2] 27 82 [2] 69 8e [2] 65 84 [2] 72 8f [2] 69 c1 [2] 54 }

  condition:
    any of them
}