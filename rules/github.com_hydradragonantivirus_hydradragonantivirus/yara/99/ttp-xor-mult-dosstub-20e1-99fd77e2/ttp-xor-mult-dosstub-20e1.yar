rule TTP_XOR_MULT_DOSStub_20e1 {
  strings:
    $key_20e1 = { 74 89 [2] 00 91 [2] 47 93 [2] 00 82 [2] 4e 8e [2] 42 84 [2] 55 8f [2] 4e c1 [2] 73 }

  condition:
    any of them
}