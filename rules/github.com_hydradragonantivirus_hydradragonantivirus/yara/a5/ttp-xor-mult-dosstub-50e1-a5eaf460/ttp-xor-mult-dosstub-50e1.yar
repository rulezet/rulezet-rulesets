rule TTP_XOR_MULT_DOSStub_50e1 {
  strings:
    $key_50e1 = { 04 89 [2] 70 91 [2] 37 93 [2] 70 82 [2] 3e 8e [2] 32 84 [2] 25 8f [2] 3e c1 [2] 03 }

  condition:
    any of them
}