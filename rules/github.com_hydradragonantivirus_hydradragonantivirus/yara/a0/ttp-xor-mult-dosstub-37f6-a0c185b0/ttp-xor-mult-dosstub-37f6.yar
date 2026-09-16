rule TTP_XOR_MULT_DOSStub_37f6 {
  strings:
    $key_37f6 = { 63 9e [2] 17 86 [2] 50 84 [2] 17 95 [2] 59 99 [2] 55 93 [2] 42 98 [2] 59 d6 [2] 64 }

  condition:
    any of them
}