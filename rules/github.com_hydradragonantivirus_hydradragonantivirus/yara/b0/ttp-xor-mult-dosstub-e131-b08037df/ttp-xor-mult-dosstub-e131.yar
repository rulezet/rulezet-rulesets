rule TTP_XOR_MULT_DOSStub_e131 {
  strings:
    $key_e131 = { b5 59 [2] c1 41 [2] 86 43 [2] c1 52 [2] 8f 5e [2] 83 54 [2] 94 5f [2] 8f 11 [2] b2 }

  condition:
    any of them
}