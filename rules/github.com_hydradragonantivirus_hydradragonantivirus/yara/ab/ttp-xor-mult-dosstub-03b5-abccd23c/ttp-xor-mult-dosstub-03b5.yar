rule TTP_XOR_MULT_DOSStub_03b5 {
  strings:
    $key_03b5 = { 57 dd [2] 23 c5 [2] 64 c7 [2] 23 d6 [2] 6d da [2] 61 d0 [2] 76 db [2] 6d 95 [2] 50 }

  condition:
    any of them
}