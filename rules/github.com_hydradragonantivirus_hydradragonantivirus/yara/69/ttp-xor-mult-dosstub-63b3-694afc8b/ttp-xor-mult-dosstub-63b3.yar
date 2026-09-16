rule TTP_XOR_MULT_DOSStub_63b3 {
  strings:
    $key_63b3 = { 37 db [2] 43 c3 [2] 04 c1 [2] 43 d0 [2] 0d dc [2] 01 d6 [2] 16 dd [2] 0d 93 [2] 30 }

  condition:
    any of them
}