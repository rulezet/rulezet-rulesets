rule TTP_XOR_MULT_DOSStub_11b5 {
  strings:
    $key_11b5 = { 45 dd [2] 31 c5 [2] 76 c7 [2] 31 d6 [2] 7f da [2] 73 d0 [2] 64 db [2] 7f 95 [2] 42 }

  condition:
    any of them
}