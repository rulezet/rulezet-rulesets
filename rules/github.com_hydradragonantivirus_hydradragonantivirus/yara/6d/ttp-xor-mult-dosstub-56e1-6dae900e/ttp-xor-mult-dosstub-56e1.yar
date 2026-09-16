rule TTP_XOR_MULT_DOSStub_56e1 {
  strings:
    $key_56e1 = { 02 89 [2] 76 91 [2] 31 93 [2] 76 82 [2] 38 8e [2] 34 84 [2] 23 8f [2] 38 c1 [2] 05 }

  condition:
    any of them
}