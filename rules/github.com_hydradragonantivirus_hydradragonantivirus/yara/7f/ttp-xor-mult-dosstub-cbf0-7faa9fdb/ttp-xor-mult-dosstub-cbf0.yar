rule TTP_XOR_MULT_DOSStub_cbf0 {
  strings:
    $key_cbf0 = { 9f 98 [2] eb 80 [2] ac 82 [2] eb 93 [2] a5 9f [2] a9 95 [2] be 9e [2] a5 d0 [2] 98 }

  condition:
    any of them
}