rule TTP_XOR_MULT_DOSStub_06b3 {
  strings:
    $key_06b3 = { 52 db [2] 26 c3 [2] 61 c1 [2] 26 d0 [2] 68 dc [2] 64 d6 [2] 73 dd [2] 68 93 [2] 55 }

  condition:
    any of them
}