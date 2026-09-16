rule TTP_XOR_MULT_DOSStub_00b5 {
  strings:
    $key_00b5 = { 54 dd [2] 20 c5 [2] 67 c7 [2] 20 d6 [2] 6e da [2] 62 d0 [2] 75 db [2] 6e 95 [2] 53 }

  condition:
    any of them
}