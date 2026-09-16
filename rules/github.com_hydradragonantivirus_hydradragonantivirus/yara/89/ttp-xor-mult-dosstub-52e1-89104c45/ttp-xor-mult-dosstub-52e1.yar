rule TTP_XOR_MULT_DOSStub_52e1 {
  strings:
    $key_52e1 = { 06 89 [2] 72 91 [2] 35 93 [2] 72 82 [2] 3c 8e [2] 30 84 [2] 27 8f [2] 3c c1 [2] 01 }

  condition:
    any of them
}