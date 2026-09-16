rule TTP_XOR_MULT_DOSStub_2006 {
  strings:
    $key_2006 = { 74 6e [2] 00 76 [2] 47 74 [2] 00 65 [2] 4e 69 [2] 42 63 [2] 55 68 [2] 4e 26 [2] 73 }

  condition:
    any of them
}