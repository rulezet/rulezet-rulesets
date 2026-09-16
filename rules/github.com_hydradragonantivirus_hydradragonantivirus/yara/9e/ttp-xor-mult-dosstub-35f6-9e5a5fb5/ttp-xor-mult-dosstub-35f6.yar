rule TTP_XOR_MULT_DOSStub_35f6 {
  strings:
    $key_35f6 = { 61 9e [2] 15 86 [2] 52 84 [2] 15 95 [2] 5b 99 [2] 57 93 [2] 40 98 [2] 5b d6 [2] 66 }

  condition:
    any of them
}