rule TTP_XOR_MULT_DOSStub_e166 {
  strings:
    $key_e166 = { b5 0e [2] c1 16 [2] 86 14 [2] c1 05 [2] 8f 09 [2] 83 03 [2] 94 08 [2] 8f 46 [2] b2 }

  condition:
    any of them
}