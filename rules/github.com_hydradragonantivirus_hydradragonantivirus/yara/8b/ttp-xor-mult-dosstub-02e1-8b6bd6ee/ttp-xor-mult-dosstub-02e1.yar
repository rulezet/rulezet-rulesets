rule TTP_XOR_MULT_DOSStub_02e1 {
  strings:
    $key_02e1 = { 56 89 [2] 22 91 [2] 65 93 [2] 22 82 [2] 6c 8e [2] 60 84 [2] 77 8f [2] 6c c1 [2] 51 }

  condition:
    any of them
}