rule TTP_XOR_MULT_DOSStub_57b2 {
  strings:
    $key_57b2 = { 03 da [2] 77 c2 [2] 30 c0 [2] 77 d1 [2] 39 dd [2] 35 d7 [2] 22 dc [2] 39 92 [2] 04 }

  condition:
    any of them
}