rule TTP_XOR_MULT_DOSStub_7136 {
  strings:
    $key_7136 = { 25 5e [2] 51 46 [2] 16 44 [2] 51 55 [2] 1f 59 [2] 13 53 [2] 04 58 [2] 1f 16 [2] 22 }

  condition:
    any of them
}