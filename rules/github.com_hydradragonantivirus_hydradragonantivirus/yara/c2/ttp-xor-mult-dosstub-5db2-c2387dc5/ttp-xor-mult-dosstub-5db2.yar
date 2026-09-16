rule TTP_XOR_MULT_DOSStub_5db2 {
  strings:
    $key_5db2 = { 09 da [2] 7d c2 [2] 3a c0 [2] 7d d1 [2] 33 dd [2] 3f d7 [2] 28 dc [2] 33 92 [2] 0e }

  condition:
    any of them
}