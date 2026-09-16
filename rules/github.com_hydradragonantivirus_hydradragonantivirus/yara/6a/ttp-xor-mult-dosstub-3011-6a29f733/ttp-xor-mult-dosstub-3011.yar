rule TTP_XOR_MULT_DOSStub_3011 {
  strings:
    $key_3011 = { 64 79 [2] 10 61 [2] 57 63 [2] 10 72 [2] 5e 7e [2] 52 74 [2] 45 7f [2] 5e 31 [2] 63 }

  condition:
    any of them
}