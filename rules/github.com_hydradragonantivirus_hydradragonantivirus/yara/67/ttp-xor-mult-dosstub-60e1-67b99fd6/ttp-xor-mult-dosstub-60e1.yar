rule TTP_XOR_MULT_DOSStub_60e1 {
  strings:
    $key_60e1 = { 34 89 [2] 40 91 [2] 07 93 [2] 40 82 [2] 0e 8e [2] 02 84 [2] 15 8f [2] 0e c1 [2] 33 }

  condition:
    any of them
}