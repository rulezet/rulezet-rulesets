rule TTP_XOR_MULT_DOSStub_37e1 {
  strings:
    $key_37e1 = { 63 89 [2] 17 91 [2] 50 93 [2] 17 82 [2] 59 8e [2] 55 84 [2] 42 8f [2] 59 c1 [2] 64 }

  condition:
    any of them
}