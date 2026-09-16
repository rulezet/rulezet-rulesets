rule TTP_XOR_MULT_DOSStub_cbfc {
  strings:
    $key_cbfc = { 9f 94 [2] eb 8c [2] ac 8e [2] eb 9f [2] a5 93 [2] a9 99 [2] be 92 [2] a5 dc [2] 98 }

  condition:
    any of them
}