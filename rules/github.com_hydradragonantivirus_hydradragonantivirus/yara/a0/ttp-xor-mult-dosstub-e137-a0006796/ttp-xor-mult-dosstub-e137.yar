rule TTP_XOR_MULT_DOSStub_e137 {
  strings:
    $key_e137 = { b5 5f [2] c1 47 [2] 86 45 [2] c1 54 [2] 8f 58 [2] 83 52 [2] 94 59 [2] 8f 17 [2] b2 }

  condition:
    any of them
}