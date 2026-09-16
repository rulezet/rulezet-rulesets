rule TTP_XOR_MULT_DOSStub_21b1 {
  strings:
    $key_21b1 = { 75 d9 [2] 01 c1 [2] 46 c3 [2] 01 d2 [2] 4f de [2] 43 d4 [2] 54 df [2] 4f 91 [2] 72 }

  condition:
    any of them
}