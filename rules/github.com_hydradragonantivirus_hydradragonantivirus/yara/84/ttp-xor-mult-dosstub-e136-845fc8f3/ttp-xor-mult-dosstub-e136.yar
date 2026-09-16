rule TTP_XOR_MULT_DOSStub_e136 {
  strings:
    $key_e136 = { b5 5e [2] c1 46 [2] 86 44 [2] c1 55 [2] 8f 59 [2] 83 53 [2] 94 58 [2] 8f 16 [2] b2 }

  condition:
    any of them
}