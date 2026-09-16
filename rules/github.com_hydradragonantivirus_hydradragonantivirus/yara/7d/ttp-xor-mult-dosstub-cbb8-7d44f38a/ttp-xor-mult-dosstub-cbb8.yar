rule TTP_XOR_MULT_DOSStub_cbb8 {
  strings:
    $key_cbb8 = { 9f d0 [2] eb c8 [2] ac ca [2] eb db [2] a5 d7 [2] a9 dd [2] be d6 [2] a5 98 [2] 98 }

  condition:
    any of them
}