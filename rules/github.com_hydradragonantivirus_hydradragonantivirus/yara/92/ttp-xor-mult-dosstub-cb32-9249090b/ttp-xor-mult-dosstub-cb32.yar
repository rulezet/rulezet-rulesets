rule TTP_XOR_MULT_DOSStub_cb32 {
  strings:
    $key_cb32 = { 9f 5a [2] eb 42 [2] ac 40 [2] eb 51 [2] a5 5d [2] a9 57 [2] be 5c [2] a5 12 [2] 98 }

  condition:
    any of them
}