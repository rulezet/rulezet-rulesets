rule TTP_XOR_MULT_DOSStub_4041 {
  strings:
    $key_4041 = { 14 29 [2] 60 31 [2] 27 33 [2] 60 22 [2] 2e 2e [2] 22 24 [2] 35 2f [2] 2e 61 [2] 13 }

  condition:
    any of them
}