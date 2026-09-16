rule TTP_XOR_MULT_DOSStub_cb48 {
  strings:
    $key_cb48 = { 9f 20 [2] eb 38 [2] ac 3a [2] eb 2b [2] a5 27 [2] a9 2d [2] be 26 [2] a5 68 [2] 98 }

  condition:
    any of them
}