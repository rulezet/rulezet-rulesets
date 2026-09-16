rule TTP_XOR_MULT_DOSStub_2a36 {
  strings:
    $key_2a36 = { 7e 5e [2] 0a 46 [2] 4d 44 [2] 0a 55 [2] 44 59 [2] 48 53 [2] 5f 58 [2] 44 16 [2] 79 }

  condition:
    any of them
}