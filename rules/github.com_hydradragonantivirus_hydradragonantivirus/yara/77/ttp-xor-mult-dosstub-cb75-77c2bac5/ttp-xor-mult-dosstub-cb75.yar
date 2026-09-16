rule TTP_XOR_MULT_DOSStub_cb75 {
  strings:
    $key_cb75 = { 9f 1d [2] eb 05 [2] ac 07 [2] eb 16 [2] a5 1a [2] a9 10 [2] be 1b [2] a5 55 [2] 98 }

  condition:
    any of them
}