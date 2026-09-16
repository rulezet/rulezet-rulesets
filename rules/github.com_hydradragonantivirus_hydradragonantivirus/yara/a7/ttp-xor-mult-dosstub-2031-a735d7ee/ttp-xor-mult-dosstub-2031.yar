rule TTP_XOR_MULT_DOSStub_2031 {
  strings:
    $key_2031 = { 74 59 [2] 00 41 [2] 47 43 [2] 00 52 [2] 4e 5e [2] 42 54 [2] 55 5f [2] 4e 11 [2] 73 }

  condition:
    any of them
}