rule TTP_XOR_MULT_DOSStub_2016 {
  strings:
    $key_2016 = { 74 7e [2] 00 66 [2] 47 64 [2] 00 75 [2] 4e 79 [2] 42 73 [2] 55 78 [2] 4e 36 [2] 73 }

  condition:
    any of them
}