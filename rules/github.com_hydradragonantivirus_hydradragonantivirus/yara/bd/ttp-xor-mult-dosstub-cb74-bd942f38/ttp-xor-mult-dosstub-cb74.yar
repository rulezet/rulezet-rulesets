rule TTP_XOR_MULT_DOSStub_cb74 {
  strings:
    $key_cb74 = { 9f 1c [2] eb 04 [2] ac 06 [2] eb 17 [2] a5 1b [2] a9 11 [2] be 1a [2] a5 54 [2] 98 }

  condition:
    any of them
}