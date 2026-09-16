rule TTP_XOR_MULT_DOSStub_1010 {
  strings:
    $key_1010 = { 44 78 [2] 30 60 [2] 77 62 [2] 30 73 [2] 7e 7f [2] 72 75 [2] 65 7e [2] 7e 30 [2] 43 }

  condition:
    any of them
}