rule TTP_XOR_MULT_DOSStub_cb72 {
  strings:
    $key_cb72 = { 9f 1a [2] eb 02 [2] ac 00 [2] eb 11 [2] a5 1d [2] a9 17 [2] be 1c [2] a5 52 [2] 98 }

  condition:
    any of them
}