rule TTP_XOR_MULT_DOSStub_e171 {
  strings:
    $key_e171 = { b5 19 [2] c1 01 [2] 86 03 [2] c1 12 [2] 8f 1e [2] 83 14 [2] 94 1f [2] 8f 51 [2] b2 }

  condition:
    any of them
}