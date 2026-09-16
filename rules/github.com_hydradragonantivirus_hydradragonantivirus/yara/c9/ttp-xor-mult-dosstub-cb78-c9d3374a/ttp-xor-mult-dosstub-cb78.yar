rule TTP_XOR_MULT_DOSStub_cb78 {
  strings:
    $key_cb78 = { 9f 10 [2] eb 08 [2] ac 0a [2] eb 1b [2] a5 17 [2] a9 1d [2] be 16 [2] a5 58 [2] 98 }

  condition:
    any of them
}