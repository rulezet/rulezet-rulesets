rule TTP_XOR_MULT_DOSStub_40e1 {
  strings:
    $key_40e1 = { 14 89 [2] 60 91 [2] 27 93 [2] 60 82 [2] 2e 8e [2] 22 84 [2] 35 8f [2] 2e c1 [2] 13 }

  condition:
    any of them
}