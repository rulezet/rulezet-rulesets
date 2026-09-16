rule TTP_XOR_MULT_DOSStub_03b3 {
  strings:
    $key_03b3 = { 57 db [2] 23 c3 [2] 64 c1 [2] 23 d0 [2] 6d dc [2] 61 d6 [2] 76 dd [2] 6d 93 [2] 50 }

  condition:
    any of them
}