rule TTP_XOR_MULT_DOSStub_2db2 {
  strings:
    $key_2db2 = { 79 da [2] 0d c2 [2] 4a c0 [2] 0d d1 [2] 43 dd [2] 4f d7 [2] 58 dc [2] 43 92 [2] 7e }

  condition:
    any of them
}