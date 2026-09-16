rule TTP_XOR_MULT_DOSStub_cbfa {
  strings:
    $key_cbfa = { 9f 92 [2] eb 8a [2] ac 88 [2] eb 99 [2] a5 95 [2] a9 9f [2] be 94 [2] a5 da [2] 98 }

  condition:
    any of them
}