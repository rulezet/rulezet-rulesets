rule TTP_XOR_MULT_DOSStub_30b5 {
  strings:
    $key_30b5 = { 64 dd [2] 10 c5 [2] 57 c7 [2] 10 d6 [2] 5e da [2] 52 d0 [2] 45 db [2] 5e 95 [2] 63 }

  condition:
    any of them
}