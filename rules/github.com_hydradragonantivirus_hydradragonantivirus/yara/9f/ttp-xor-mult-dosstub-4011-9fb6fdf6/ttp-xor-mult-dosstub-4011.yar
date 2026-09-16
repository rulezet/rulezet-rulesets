rule TTP_XOR_MULT_DOSStub_4011 {
  strings:
    $key_4011 = { 14 79 [2] 60 61 [2] 27 63 [2] 60 72 [2] 2e 7e [2] 22 74 [2] 35 7f [2] 2e 31 [2] 13 }

  condition:
    any of them
}