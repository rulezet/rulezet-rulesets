rule TTP_XOR_MULT_DOSStub_cbdd {
  strings:
    $key_cbdd = { 9f b5 [2] eb ad [2] ac af [2] eb be [2] a5 b2 [2] a9 b8 [2] be b3 [2] a5 fd [2] 98 }

  condition:
    any of them
}