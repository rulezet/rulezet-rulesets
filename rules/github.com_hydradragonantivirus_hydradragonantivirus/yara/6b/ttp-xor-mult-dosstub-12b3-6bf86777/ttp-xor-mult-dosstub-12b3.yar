rule TTP_XOR_MULT_DOSStub_12b3 {
  strings:
    $key_12b3 = { 46 db [2] 32 c3 [2] 75 c1 [2] 32 d0 [2] 7c dc [2] 70 d6 [2] 67 dd [2] 7c 93 [2] 41 }

  condition:
    any of them
}