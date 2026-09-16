rule TTP_XOR_MULT_DOSStub_7b10 {
  strings:
    $key_7b10 = { 2f 78 [2] 5b 60 [2] 1c 62 [2] 5b 73 [2] 15 7f [2] 19 75 [2] 0e 7e [2] 15 30 [2] 28 }

  condition:
    any of them
}