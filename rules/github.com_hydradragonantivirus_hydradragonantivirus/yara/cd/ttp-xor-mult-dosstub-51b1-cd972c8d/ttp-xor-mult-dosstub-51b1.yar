rule TTP_XOR_MULT_DOSStub_51b1 {
  strings:
    $key_51b1 = { 05 d9 [2] 71 c1 [2] 36 c3 [2] 71 d2 [2] 3f de [2] 33 d4 [2] 24 df [2] 3f 91 [2] 02 }

  condition:
    any of them
}