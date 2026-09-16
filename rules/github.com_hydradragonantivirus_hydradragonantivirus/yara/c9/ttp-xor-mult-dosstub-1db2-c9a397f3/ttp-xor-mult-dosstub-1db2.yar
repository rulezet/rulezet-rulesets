rule TTP_XOR_MULT_DOSStub_1db2 {
  strings:
    $key_1db2 = { 49 da [2] 3d c2 [2] 7a c0 [2] 3d d1 [2] 73 dd [2] 7f d7 [2] 68 dc [2] 73 92 [2] 4e }

  condition:
    any of them
}