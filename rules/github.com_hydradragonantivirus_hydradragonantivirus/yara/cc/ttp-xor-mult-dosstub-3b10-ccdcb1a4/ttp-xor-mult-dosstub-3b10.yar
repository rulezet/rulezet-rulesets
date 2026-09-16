rule TTP_XOR_MULT_DOSStub_3b10 {
  strings:
    $key_3b10 = { 6f 78 [2] 1b 60 [2] 5c 62 [2] 1b 73 [2] 55 7f [2] 59 75 [2] 4e 7e [2] 55 30 [2] 68 }

  condition:
    any of them
}