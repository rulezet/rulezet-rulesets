rule TTP_XOR_MULT_DOSStub_61b5 {
  strings:
    $key_61b5 = { 35 dd [2] 41 c5 [2] 06 c7 [2] 41 d6 [2] 0f da [2] 03 d0 [2] 14 db [2] 0f 95 [2] 32 }

  condition:
    any of them
}