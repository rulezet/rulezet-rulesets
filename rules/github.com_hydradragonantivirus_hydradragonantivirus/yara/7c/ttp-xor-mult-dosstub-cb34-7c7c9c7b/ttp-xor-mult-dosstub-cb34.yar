rule TTP_XOR_MULT_DOSStub_cb34 {
  strings:
    $key_cb34 = { 9f 5c [2] eb 44 [2] ac 46 [2] eb 57 [2] a5 5b [2] a9 51 [2] be 5a [2] a5 14 [2] 98 }

  condition:
    any of them
}