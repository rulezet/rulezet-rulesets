rule TTP_XOR_MULT_DOSStub_cb50 {
  strings:
    $key_cb50 = { 9f 38 [2] eb 20 [2] ac 22 [2] eb 33 [2] a5 3f [2] a9 35 [2] be 3e [2] a5 70 [2] 98 }

  condition:
    any of them
}