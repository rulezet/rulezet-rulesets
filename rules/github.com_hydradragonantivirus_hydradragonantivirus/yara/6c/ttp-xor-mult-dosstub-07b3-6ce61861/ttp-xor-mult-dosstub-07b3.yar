rule TTP_XOR_MULT_DOSStub_07b3 {
  strings:
    $key_07b3 = { 53 db [2] 27 c3 [2] 60 c1 [2] 27 d0 [2] 69 dc [2] 65 d6 [2] 72 dd [2] 69 93 [2] 54 }

  condition:
    any of them
}