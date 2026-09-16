rule TTP_XOR_MULT_DOSStub_cb41 {
  strings:
    $key_cb41 = { 9f 29 [2] eb 31 [2] ac 33 [2] eb 22 [2] a5 2e [2] a9 24 [2] be 2f [2] a5 61 [2] 98 }

  condition:
    any of them
}