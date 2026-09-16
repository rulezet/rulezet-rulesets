rule TTP_XOR_MULT_DOSStub_cbbe {
  strings:
    $key_cbbe = { 9f d6 [2] eb ce [2] ac cc [2] eb dd [2] a5 d1 [2] a9 db [2] be d0 [2] a5 9e [2] 98 }

  condition:
    any of them
}