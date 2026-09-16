rule TTP_XOR_MULT_DOSStub_11b1 {
  strings:
    $key_11b1 = { 45 d9 [2] 31 c1 [2] 76 c3 [2] 31 d2 [2] 7f de [2] 73 d4 [2] 64 df [2] 7f 91 [2] 42 }

  condition:
    any of them
}