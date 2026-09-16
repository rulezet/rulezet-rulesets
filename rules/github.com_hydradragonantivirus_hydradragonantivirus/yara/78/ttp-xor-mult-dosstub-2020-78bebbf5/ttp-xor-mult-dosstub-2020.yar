rule TTP_XOR_MULT_DOSStub_2020 {
  strings:
    $key_2020 = { 74 48 [2] 00 50 [2] 47 52 [2] 00 43 [2] 4e 4f [2] 42 45 [2] 55 4e [2] 4e 00 [2] 73 }

  condition:
    any of them
}