rule TTP_XOR_MULT_DOSStub_0136 {
  strings:
    $key_0136 = { 55 5e [2] 21 46 [2] 66 44 [2] 21 55 [2] 6f 59 [2] 63 53 [2] 74 58 [2] 6f 16 [2] 52 }

  condition:
    any of them
}