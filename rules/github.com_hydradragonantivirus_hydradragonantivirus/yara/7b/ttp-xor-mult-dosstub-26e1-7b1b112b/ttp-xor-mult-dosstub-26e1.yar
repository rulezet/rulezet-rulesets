rule TTP_XOR_MULT_DOSStub_26e1 {
  strings:
    $key_26e1 = { 72 89 [2] 06 91 [2] 41 93 [2] 06 82 [2] 48 8e [2] 44 84 [2] 53 8f [2] 48 c1 [2] 75 }

  condition:
    any of them
}