rule TTP_XOR_MULT_DOSStub_cbb3 {
  strings:
    $key_cbb3 = { 9f db [2] eb c3 [2] ac c1 [2] eb d0 [2] a5 dc [2] a9 d6 [2] be dd [2] a5 93 [2] 98 }

  condition:
    any of them
}