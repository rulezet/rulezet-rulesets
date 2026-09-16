rule TTP_XOR_MULT_DOSStub_e7e1 {
  strings:
    $key_e7e1 = { b3 89 [2] c7 91 [2] 80 93 [2] c7 82 [2] 89 8e [2] 85 84 [2] 92 8f [2] 89 c1 [2] b4 }

  condition:
    any of them
}