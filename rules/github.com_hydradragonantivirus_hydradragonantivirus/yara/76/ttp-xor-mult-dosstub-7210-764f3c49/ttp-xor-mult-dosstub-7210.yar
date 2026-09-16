rule TTP_XOR_MULT_DOSStub_7210 {
  strings:
    $key_7210 = { 26 78 [2] 52 60 [2] 15 62 [2] 52 73 [2] 1c 7f [2] 10 75 [2] 07 7e [2] 1c 30 [2] 21 }

  condition:
    any of them
}