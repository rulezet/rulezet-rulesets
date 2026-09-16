rule TTP_XOR_MULT_DOSStub_0b10 {
  strings:
    $key_0b10 = { 5f 78 [2] 2b 60 [2] 6c 62 [2] 2b 73 [2] 65 7f [2] 69 75 [2] 7e 7e [2] 65 30 [2] 58 }

  condition:
    any of them
}