rule TTP_XOR_MULT_DOSStub_22b5 {
  strings:
    $key_22b5 = { 76 dd [2] 02 c5 [2] 45 c7 [2] 02 d6 [2] 4c da [2] 40 d0 [2] 57 db [2] 4c 95 [2] 71 }

  condition:
    any of them
}