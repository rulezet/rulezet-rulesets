rule TTP_XOR_MULT_DOSStub_61b1 {
  strings:
    $key_61b1 = { 35 d9 [2] 41 c1 [2] 06 c3 [2] 41 d2 [2] 0f de [2] 03 d4 [2] 14 df [2] 0f 91 [2] 32 }

  condition:
    any of them
}