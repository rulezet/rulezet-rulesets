rule TTP_XOR_MULT_DOSStub_3706 {
  strings:
    $key_3706 = { 63 6e [2] 17 76 [2] 50 74 [2] 17 65 [2] 59 69 [2] 55 63 [2] 42 68 [2] 59 26 [2] 64 }

  condition:
    any of them
}