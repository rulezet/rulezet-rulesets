rule TTP_XOR_MULT_DOSStub_4b10 {
  strings:
    $key_4b10 = { 1f 78 [2] 6b 60 [2] 2c 62 [2] 6b 73 [2] 25 7f [2] 29 75 [2] 3e 7e [2] 25 30 [2] 18 }

  condition:
    any of them
}