rule TTP_XOR_MULT_DOSStub_37b1 {
  strings:
    $key_37b1 = { 63 d9 [2] 17 c1 [2] 50 c3 [2] 17 d2 [2] 59 de [2] 55 d4 [2] 42 df [2] 59 91 [2] 64 }

  condition:
    any of them
}