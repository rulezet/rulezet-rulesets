rule TTP_XOR_MULT_DOSStub_2011 {
  strings:
    $key_2011 = { 74 79 [2] 00 61 [2] 47 63 [2] 00 72 [2] 4e 7e [2] 42 74 [2] 55 7f [2] 4e 31 [2] 73 }

  condition:
    any of them
}