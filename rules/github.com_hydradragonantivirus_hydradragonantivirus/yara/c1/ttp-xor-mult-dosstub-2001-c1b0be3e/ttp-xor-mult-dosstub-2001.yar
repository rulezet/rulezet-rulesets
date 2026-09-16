rule TTP_XOR_MULT_DOSStub_2001 {
  strings:
    $key_2001 = { 74 69 [2] 00 71 [2] 47 73 [2] 00 62 [2] 4e 6e [2] 42 64 [2] 55 6f [2] 4e 21 [2] 73 }

  condition:
    any of them
}