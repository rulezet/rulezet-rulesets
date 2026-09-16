rule TTP_XOR_MULT_DOSStub_cb56 {
  strings:
    $key_cb56 = { 9f 3e [2] eb 26 [2] ac 24 [2] eb 35 [2] a5 39 [2] a9 33 [2] be 38 [2] a5 76 [2] 98 }

  condition:
    any of them
}