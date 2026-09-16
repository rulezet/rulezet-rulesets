rule TTP_XOR_MULT_DOSStub_52b3 {
  strings:
    $key_52b3 = { 06 db [2] 72 c3 [2] 35 c1 [2] 72 d0 [2] 3c dc [2] 30 d6 [2] 27 dd [2] 3c 93 [2] 01 }

  condition:
    any of them
}