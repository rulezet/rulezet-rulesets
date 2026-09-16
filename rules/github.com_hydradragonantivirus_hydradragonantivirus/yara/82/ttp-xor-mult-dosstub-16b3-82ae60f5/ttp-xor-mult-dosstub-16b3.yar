rule TTP_XOR_MULT_DOSStub_16b3 {
  strings:
    $key_16b3 = { 42 db [2] 36 c3 [2] 71 c1 [2] 36 d0 [2] 78 dc [2] 74 d6 [2] 63 dd [2] 78 93 [2] 45 }

  condition:
    any of them
}