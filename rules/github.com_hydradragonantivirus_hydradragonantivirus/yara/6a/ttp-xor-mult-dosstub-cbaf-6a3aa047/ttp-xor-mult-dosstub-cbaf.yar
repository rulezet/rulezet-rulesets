rule TTP_XOR_MULT_DOSStub_cbaf {
  strings:
    $key_cbaf = { 9f c7 [2] eb df [2] ac dd [2] eb cc [2] a5 c0 [2] a9 ca [2] be c1 [2] a5 8f [2] 98 }

  condition:
    any of them
}