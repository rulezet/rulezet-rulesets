rule TTP_XOR_MULT_DOSStub_e170 {
  strings:
    $key_e170 = { b5 18 [2] c1 00 [2] 86 02 [2] c1 13 [2] 8f 1f [2] 83 15 [2] 94 1e [2] 8f 50 [2] b2 }

  condition:
    any of them
}