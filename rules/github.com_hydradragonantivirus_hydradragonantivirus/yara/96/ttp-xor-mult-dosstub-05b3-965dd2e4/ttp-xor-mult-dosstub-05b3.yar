rule TTP_XOR_MULT_DOSStub_05b3 {
  strings:
    $key_05b3 = { 51 db [2] 25 c3 [2] 62 c1 [2] 25 d0 [2] 6b dc [2] 67 d6 [2] 70 dd [2] 6b 93 [2] 56 }

  condition:
    any of them
}