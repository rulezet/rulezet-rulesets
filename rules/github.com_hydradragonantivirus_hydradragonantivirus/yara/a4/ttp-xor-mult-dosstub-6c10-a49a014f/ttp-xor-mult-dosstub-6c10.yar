rule TTP_XOR_MULT_DOSStub_6c10 {
  strings:
    $key_6c10 = { 38 78 [2] 4c 60 [2] 0b 62 [2] 4c 73 [2] 02 7f [2] 0e 75 [2] 19 7e [2] 02 30 [2] 3f }

  condition:
    any of them
}