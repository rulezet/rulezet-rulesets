rule TTP_XOR_MULT_DOSStub_cbb5 {
  strings:
    $key_cbb5 = { 9f dd [2] eb c5 [2] ac c7 [2] eb d6 [2] a5 da [2] a9 d0 [2] be db [2] a5 95 [2] 98 }

  condition:
    any of them
}