rule TTP_XOR_MULT_DOSStub_65b3 {
  strings:
    $key_65b3 = { 31 db [2] 45 c3 [2] 02 c1 [2] 45 d0 [2] 0b dc [2] 07 d6 [2] 10 dd [2] 0b 93 [2] 36 }

  condition:
    any of them
}