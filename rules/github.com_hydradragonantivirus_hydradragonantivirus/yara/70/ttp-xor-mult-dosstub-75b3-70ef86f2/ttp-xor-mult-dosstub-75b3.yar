rule TTP_XOR_MULT_DOSStub_75b3 {
  strings:
    $key_75b3 = { 21 db [2] 55 c3 [2] 12 c1 [2] 55 d0 [2] 1b dc [2] 17 d6 [2] 00 dd [2] 1b 93 [2] 26 }

  condition:
    any of them
}