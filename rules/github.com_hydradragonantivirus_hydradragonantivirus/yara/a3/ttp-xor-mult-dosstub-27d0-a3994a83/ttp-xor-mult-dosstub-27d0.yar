rule TTP_XOR_MULT_DOSStub_27d0 {
  strings:
    $key_27d0 = { 73 b8 [2] 07 a0 [2] 40 a2 [2] 07 b3 [2] 49 bf [2] 45 b5 [2] 52 be [2] 49 f0 [2] 74 }

  condition:
    any of them
}