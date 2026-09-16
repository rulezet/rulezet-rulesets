rule TTP_XOR_MULT_DOSStub_32b5 {
  strings:
    $key_32b5 = { 66 dd [2] 12 c5 [2] 55 c7 [2] 12 d6 [2] 5c da [2] 50 d0 [2] 47 db [2] 5c 95 [2] 61 }

  condition:
    any of them
}