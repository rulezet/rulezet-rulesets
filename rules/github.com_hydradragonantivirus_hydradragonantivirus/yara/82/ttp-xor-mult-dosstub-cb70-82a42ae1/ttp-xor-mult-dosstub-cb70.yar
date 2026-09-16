rule TTP_XOR_MULT_DOSStub_cb70 {
  strings:
    $key_cb70 = { 9f 18 [2] eb 00 [2] ac 02 [2] eb 13 [2] a5 1f [2] a9 15 [2] be 1e [2] a5 50 [2] 98 }

  condition:
    any of them
}