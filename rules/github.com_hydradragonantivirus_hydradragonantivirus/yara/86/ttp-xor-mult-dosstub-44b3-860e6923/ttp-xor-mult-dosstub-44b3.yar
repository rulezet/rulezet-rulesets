rule TTP_XOR_MULT_DOSStub_44b3 {
  strings:
    $key_44b3 = { 10 db [2] 64 c3 [2] 23 c1 [2] 64 d0 [2] 2a dc [2] 26 d6 [2] 31 dd [2] 2a 93 [2] 17 }

  condition:
    any of them
}