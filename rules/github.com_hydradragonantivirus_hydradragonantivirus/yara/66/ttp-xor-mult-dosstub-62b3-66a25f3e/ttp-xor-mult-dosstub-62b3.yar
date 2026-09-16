rule TTP_XOR_MULT_DOSStub_62b3 {
  strings:
    $key_62b3 = { 36 db [2] 42 c3 [2] 05 c1 [2] 42 d0 [2] 0c dc [2] 00 d6 [2] 17 dd [2] 0c 93 [2] 31 }

  condition:
    any of them
}