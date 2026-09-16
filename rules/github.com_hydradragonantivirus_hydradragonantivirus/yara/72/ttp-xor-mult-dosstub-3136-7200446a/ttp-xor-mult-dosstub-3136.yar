rule TTP_XOR_MULT_DOSStub_3136 {
  strings:
    $key_3136 = { 65 5e [2] 11 46 [2] 56 44 [2] 11 55 [2] 5f 59 [2] 53 53 [2] 44 58 [2] 5f 16 [2] 62 }

  condition:
    any of them
}